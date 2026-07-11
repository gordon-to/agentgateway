use std::path::Path;
use std::time::Duration;

use agent_core::prelude::*;
use agent_core::readiness;

use crate::client::Client;
use crate::store::Stores;
use crate::types::agent::ListenerTarget;
use crate::types::discovery::SelfIdentitySource;
use crate::types::proto::agent::Resource as ADPResource;
use crate::types::proto::workload::Address as XdsAddress;
use crate::{ConfigSource, client, control, store};

#[derive(serde::Serialize)]
pub struct StateManager {
	#[serde(flatten)]
	stores: Stores,

	#[serde(skip_serializing)]
	xds_client: Option<agent_xds::AdsClient>,

	#[serde(skip_serializing)]
	resource_manager: crate::resource_manager::ResourceManager,

	#[serde(skip_serializing)]
	local_client: Option<LocalClient>,
}

pub const ADDRESS_TYPE: Strng = strng::literal!("type.googleapis.com/istio.workload.Address");
pub const AUTHORIZATION_TYPE: Strng =
	strng::literal!("type.googleapis.com/istio.security.Authorization");
pub const ADP_TYPE: Strng =
	strng::literal!("type.googleapis.com/agentgateway.dev.resource.Resource");

impl StateManager {
	pub async fn new(
		config: Arc<crate::Config>,
		client: client::Client,
		config_metrics: Arc<agent_xds::Metrics>,
		awaiting_ready: tokio::sync::watch::Sender<()>,
	) -> anyhow::Result<Self> {
		let xds = &config.xds;
		let stores = Stores::new_with_dynamic_ca_cert_cache(
			config.ipv6_enabled,
			config.threading_mode,
			config.dynamic_ca_cert_cache.clone(),
		);
		let resource_manager = crate::resource_manager::ResourceManager::new(client.clone())?;
		let xds_client = if let Some(addr) = &xds.address {
			let connector = control::grpc_connector(
				client.clone(),
				addr.clone(),
				xds.auth.clone(),
				xds.ca_cert.clone(),
				vec![],
			)
			.await?;
			Some(
				agent_xds::Config::new(
					agent_xds::GrpcClient::new(connector),
					xds.gateway.clone(),
					xds.namespace.clone(),
				)
				.with_watched_handler::<XdsAddress>(ADDRESS_TYPE, stores.clone().discovery.clone())
				.with_watched_handler::<ADPResource>(ADP_TYPE, stores.clone().binds.clone())
				// .with_watched_handler::<XdsAuthorization>(AUTHORIZATION_TYPE, state)
				.build(config_metrics.clone(), awaiting_ready),
			)
		} else {
			None
		};
		let local_client = if let Some(cfg) = &xds.local_config {
			let local_client = LocalClient {
				config: config.clone(),
				stores: stores.clone(),
				cfg: cfg.clone(),
				client,
				resource_manager: resource_manager.clone(),
				gateway: ListenerTarget {
					gateway_name: xds.gateway.clone(),
					gateway_namespace: xds.namespace.clone(),
					listener_name: None,
					port: None,
				},
				metrics: config_metrics,
				status: Default::default(),
			};
			Box::pin(local_client.clone().run()).await?;
			Some(local_client)
		} else {
			None
		};
		Ok(Self {
			stores,
			xds_client,
			resource_manager,
			local_client,
		})
	}

	pub fn stores(&self) -> Stores {
		self.stores.clone()
	}

	pub fn resource_manager(&self) -> crate::resource_manager::ResourceManager {
		self.resource_manager.clone()
	}

	pub fn local_client(&self) -> Option<LocalClient> {
		self.local_client.clone()
	}

	pub async fn run(self) -> anyhow::Result<()> {
		match self.xds_client {
			Some(xds) => xds.run().await.map_err(|e| anyhow::anyhow!(e)),
			None => Ok(()),
		}
	}
}

/// LoadStatus reports the outcome of the most recent local config load. It is
/// written by [`LocalClient`] alongside the `config_synchronized` metric and
/// read via [`LocalClient::load_status`].
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadStatus {
	running_hash: Option<String>,
	disk_hash: Option<String>,
	error: Option<String>,
	last_updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn content_hash(content: &str) -> String {
	use sha2::Digest as _;
	format!(
		"sha256:{}",
		hex::encode(sha2::Sha256::digest(content.as_bytes()))
	)
}

/// LocalClient loads configuration from a local file or static content and
/// watches it for changes. Standalone (non-XDS) deployments configure the
/// gateway through this client.
#[derive(Debug, Clone)]
pub struct LocalClient {
	config: Arc<crate::Config>,
	pub cfg: ConfigSource,
	pub stores: Stores,
	pub client: Client,
	pub resource_manager: crate::resource_manager::ResourceManager,
	pub gateway: ListenerTarget,
	pub metrics: Arc<agent_xds::Metrics>,
	status: Arc<std::sync::RwLock<LoadStatus>>,
}

impl LocalClient {
	/// Returns the status of the most recent config load, with `disk_hash`
	/// computed from the current config source content.
	pub async fn load_status(&self) -> LoadStatus {
		let mut status = self.status.read().expect("mutex acquired").clone();
		status.disk_hash = self
			.cfg
			.read_to_string()
			.await
			.ok()
			.map(|c| content_hash(&c));
		status
	}

	pub async fn run(self) -> Result<(), anyhow::Error> {
		let next_state = self.reload_config(PreviousState::default()).await?;
		if let ConfigSource::File(path) = &self.cfg {
			self.watch_config_file(path, next_state).await?;
		} else {
			self.watch_resource_changes(next_state);
		}

		Ok(())
	}

	async fn watch_config_file(
		&self,
		path: &Path,
		mut next_state: PreviousState,
	) -> anyhow::Result<()> {
		let watch_options = crate::util::WatchFilesOptions::default().close_on_removal(true);
		let mut watched =
			crate::util::watch_files_with_options(vec![path.to_path_buf()], watch_options)?;
		info!("Watching config file: {}", path.display());

		let lc: LocalClient = self.to_owned();
		let path = path.to_path_buf();
		let mut resource_changes = lc.resource_manager.subscribe_changes();
		tokio::task::spawn(async move {
			loop {
				tokio::select! {
					changed = watched.changed_invalidated() => {
						let Some(invalidated) = changed else {
							break;
						};
						next_state = lc.reload_config_after_change(next_state).await;
						if invalidated {
							match crate::util::watch_files_with_options(vec![path.clone()], watch_options) {
								Ok(new_watched) => watched = new_watched,
								Err(e) => {
									warn!("failed to re-watch config file {}: {e}", path.display());
									break;
								},
							}
						}
					}
					changed = resource_changes.changed() => {
						if changed.is_err() {
							break;
						}
						let resource = resource_changes.borrow().resource.clone();
						info!(resource, "resource changed, reloading");
						next_state = lc.reload_config_after_change(next_state).await;
					}
				}
			}
		});

		Ok(())
	}

	fn watch_resource_changes(&self, mut next_state: PreviousState) {
		let lc = self.clone();
		let mut resource_changes = self.resource_manager.subscribe_changes();
		tokio::task::spawn(async move {
			while resource_changes.changed().await.is_ok() {
				let resource = resource_changes.borrow().resource.clone();
				info!(resource, "resource changed, reloading");
				next_state = lc.reload_config_after_change(next_state).await;
			}
		});
	}

	async fn reload_config(&self, prev: PreviousState) -> anyhow::Result<PreviousState> {
		let config_content = self.cfg.read_to_string().await?;
		let resources =
			crate::resource_manager::ResourceFetcher::managed(self.resource_manager.clone());
		let config = crate::types::local::NormalizedLocalConfig::from(
			&self.config,
			&resources,
			self.gateway.clone(),
			config_content.as_str(),
		)
		.await?;
		info!("loaded config from {:?}", self.cfg);

		// Sync the state
		let next_binds = self.stores.binds.sync_local(
			config.binds,
			config.listener_routes,
			config.listener_tcp_routes,
			config.policies,
			config.backends,
			config.route_groups,
			prev.binds,
		);
		let next_discovery =
			self
				.stores
				.discovery
				.sync_local(config.services, config.workloads, prev.discovery)?;

		{
			let mut status = self.status.write().expect("mutex acquired");
			status.running_hash = Some(content_hash(&config_content));
			status.error = None;
			status.last_updated_at = Some(chrono::Utc::now());
		}

		Ok(PreviousState {
			binds: next_binds,
			discovery: next_discovery,
		})
	}

	async fn reload_config_after_change(&self, prev: PreviousState) -> PreviousState {
		debug!("Config dependency changed, reloading...");
		match self.reload_config(prev.clone()).await {
			Ok(nxt) => {
				self.metrics.config_synchronized.set(1);
				debug!("Config reloaded successfully");
				nxt
			},
			Err(e) => {
				// Record the error before the gauge flips so observers of the metric see it
				{
					let mut status = self.status.write().expect("mutex acquired");
					status.error = Some(format!("{e:#}"));
					status.last_updated_at = Some(chrono::Utc::now());
				}
				self.metrics.config_synchronized.set(0);
				error!("Failed to reload config: {}", e);
				prev
			},
		}
	}
}

#[derive(Clone, Debug, Default)]
pub struct PreviousState {
	pub binds: store::BindPreviousState,
	pub discovery: store::DiscoveryPreviousState,
}

const SELF_WORKLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Populates the discovery store's self_workload according to `config.self_identity`.
///
/// For `Static`, sets the cached workload synchronously and rebuckets.
/// For `Wds`, blocks readiness until WDS delivers the workload or timeout expires.
pub fn start_self_workload_resolution(
	config: &crate::Config,
	stores: Stores,
	ready: &readiness::Ready,
) {
	match &config.self_identity {
		Some(SelfIdentitySource::Static(w)) => {
			let store = stores.discovery.read();
			store.self_workload.set((**w).clone());
			store.rebucket_all();
		},
		Some(SelfIdentitySource::Wds {
			name,
			namespace,
			cluster_id,
		}) => {
			let task = ready.register_task("self workload");
			let name = name.clone();
			let namespace = namespace.clone();
			let cluster_id = cluster_id.clone();
			let has_xds = config.xds.address.is_some();
			tokio::spawn(async move {
				watch_self_workload(stores, name, namespace, cluster_id, Some(task), has_xds).await;
			});
		},
		None => {},
	}
}

async fn watch_self_workload(
	stores: Stores,
	name: Strng,
	namespace: Strng,
	cluster_id: Strng,
	mut ready_task: Option<readiness::BlockReady>,
	has_xds: bool,
) {
	let mut inserts = stores.discovery.read().workloads.subscribe_inserts();

	// allow a cluster id mismatch as a very common misconfiguration is that the control plane and
	// dataplane mismatch on this but if we do hit a conflict (should be rare) we use the cluster_id
	// as a tiebreaker
	let lookup = || {
		let store = stores.discovery.read();
		store
			.workloads
			.find_by_name(&name, &namespace)
			.max_by_key(|w| w.cluster_id == cluster_id)
			.cloned()
	};

	{
		let store = stores.discovery.read();
		if let Some(w) = lookup() {
			store.self_workload.set((*w).clone());
			store.rebucket_all();
			return;
		}
	}

	// Without XDS nothing will ever insert workloads; drop the task and stop.
	if !has_xds {
		return;
	}

	// wait for any change before starting our timeout if the control plane is down, or xDS is
	// otherwise slow we don't want to bail early without locality info
	if inserts.changed().await.is_err() {
		return;
	}

	let deadline = tokio::time::sleep(SELF_WORKLOAD_TIMEOUT);
	tokio::pin!(deadline);
	loop {
		{
			let store = stores.discovery.read();
			if let Some(w) = lookup() {
				store.self_workload.set((*w).clone());
				store.rebucket_all();
				return;
			}
		}
		tokio::select! {
			_ = &mut deadline, if ready_task.is_some() => {
				warn!(
					%namespace, %name,
					"timed out waiting for own workload in WDS after {:?}; unblocking readiness, still watching",
					SELF_WORKLOAD_TIMEOUT
				);
				// drop the task, but keep looping so we can still populate the self_workload if it shows up later
				ready_task = None;
			}
			r = inserts.changed() => {
				if r.is_err() {
					return;
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use agent_core::readiness::Ready;

	use super::*;
	use crate::ConfigSource;
	use crate::store::{DiscoveryPreviousState, LocalWorkload, Stores};
	use crate::types::discovery::Workload;

	const TASK_NAME: &str = "self workload";

	fn test_config() -> crate::Config {
		crate::config::parse_config("{}".to_string(), None).expect("parse default config")
	}

	fn test_stores() -> Stores {
		Stores::new(false, crate::ThreadingMode::Multithreaded)
	}

	fn test_client() -> Client {
		Client::new(
			&client::Config {
				resolver_cfg: hickory_resolver::config::ResolverConfig::default(),
				resolver_opts: hickory_resolver::config::ResolverOpts::default(),
			},
			None,
			crate::BackendConfig::default(),
			None,
		)
	}

	fn local_config(remove_field: &str) -> String {
		format!(
			r#"
frontendPolicies:
  accessLog:
    remove:
    - {remove_field}
"#
		)
	}

	fn wds_identity(name: &str, ns: &str, cluster: &str) -> SelfIdentitySource {
		SelfIdentitySource::Wds {
			name: name.into(),
			namespace: ns.into(),
			cluster_id: cluster.into(),
		}
	}

	async fn wait_task_dropped(ready: &Ready) {
		while ready.pending().contains(TASK_NAME) {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	}

	async fn replace_config(path: &Path, remove_field: &str) {
		let replacement = path.with_extension(format!("{remove_field}.tmp"));
		fs_err::tokio::write(&replacement, local_config(remove_field))
			.await
			.unwrap();
		fs_err::rename(&replacement, path).unwrap();
	}

	async fn wait_for_access_log_remove(config: &crate::Config, stores: &Stores, remove_field: &str) {
		tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				let frontend = stores.binds.read().frontend_policies(config.gateway_ref());
				if frontend
					.access_log
					.as_ref()
					.is_some_and(|access_log| access_log.remove.contains(remove_field))
				{
					return;
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.unwrap_or_else(|_| panic!("timed out waiting for access log remove {remove_field}"));
	}

	#[tokio::test]
	async fn wds_without_xds_must_not_block_readiness_forever() {
		let mut config = test_config();
		assert!(
			config.xds.address.is_none(),
			"precondition violated — XDS_ADDRESS leaked from env"
		);
		config.self_identity = Some(wds_identity("gw", "ns", "c"));

		let stores = test_stores();
		let ready = Ready::new();
		start_self_workload_resolution(&config, stores, &ready);

		assert!(ready.pending().contains(TASK_NAME));

		tokio::time::timeout(Duration::from_secs(5), wait_task_dropped(&ready))
			.await
			.expect("'self workload' readiness task blocked forever without XDS");
	}

	#[tokio::test]
	async fn wds_populates_self_workload_when_matching_workload_is_inserted() {
		let mut config = test_config();
		config.xds.address = Some("http://example.invalid:15010".to_string());
		config.self_identity = Some(wds_identity("gw", "ns", "c"));

		let stores = test_stores();
		let ready = Ready::new();
		start_self_workload_resolution(&config, stores.clone(), &ready);

		let workload = Workload {
			uid: "uid-1".into(),
			name: "gw".into(),
			namespace: "ns".into(),
			cluster_id: "c".into(),
			..Default::default()
		};
		stores
			.discovery
			.sync_local(
				vec![],
				vec![LocalWorkload {
					workload,
					services: Default::default(),
				}],
				DiscoveryPreviousState::default(),
			)
			.expect("sync_local");

		tokio::time::timeout(Duration::from_secs(5), wait_task_dropped(&ready))
			.await
			.expect("task should clear once matching workload is inserted");
		assert!(stores.discovery.read().self_workload.get().is_some());
	}

	#[cfg(feature = "ui")]
	async fn spawn_admin(
		config: Arc<crate::Config>,
		stores: Stores,
		resource_manager: crate::resource_manager::ResourceManager,
		local_client: Option<LocalClient>,
	) -> (std::net::SocketAddr, agent_core::drain::DrainTrigger) {
		let shutdown = agent_core::signal::Shutdown::new();
		let (drain_tx, drain_rx) = agent_core::drain::new();
		let svc = crate::management::admin::Service::new(
			config,
			crate::llm::cost::ModelCatalog::empty(),
			stores,
			resource_manager,
			local_client,
			shutdown.trigger(),
			drain_rx,
			tokio::runtime::Handle::current(),
		)
		.await
		.expect("admin server should bind");
		let addr = svc.address().expect("admin server should have an address");
		svc.spawn();
		(addr, drain_tx)
	}

	async fn wait_for_failed_reload(metrics: &agent_xds::Metrics) {
		tokio::time::timeout(Duration::from_secs(5), async {
			while metrics.config_synchronized.get() != 0 {
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("timed out waiting for reload failure");
	}

	struct LocalSetup {
		config: Arc<crate::Config>,
		stores: Stores,
		metrics: Arc<agent_xds::Metrics>,
		local_client: LocalClient,
	}

	async fn start_local_client(path: &Path) -> LocalSetup {
		let mut config =
			crate::config::parse_config("config:\n  adminAddr: localhost:0\n".to_string(), None)
				.expect("parse config");
		config.xds.local_config = Some(ConfigSource::File(path.to_path_buf()));
		let config = Arc::new(config);
		let stores = test_stores();
		let mut registry = prometheus_client::registry::Registry::default();
		let metrics = Arc::new(agent_xds::Metrics::new(&mut registry));
		let client = test_client();
		let resource_manager =
			crate::resource_manager::ResourceManager::new(client.clone()).expect("resource manager");
		let local_client = LocalClient {
			config: config.clone(),
			cfg: ConfigSource::File(path.to_path_buf()),
			stores: stores.clone(),
			client,
			resource_manager,
			gateway: config.gateway(),
			metrics: metrics.clone(),
			status: Default::default(),
		};
		local_client
			.clone()
			.run()
			.await
			.expect("initial config load");
		LocalSetup {
			config,
			stores,
			metrics,
			local_client,
		}
	}

	#[cfg(feature = "ui")]
	struct LiveGateway {
		config: Arc<crate::Config>,
		stores: Stores,
		metrics: Arc<agent_xds::Metrics>,
		addr: std::net::SocketAddr,
		_drain_tx: agent_core::drain::DrainTrigger,
	}

	#[cfg(feature = "ui")]
	async fn start_gateway_with_config_file(path: &Path) -> LiveGateway {
		let setup = start_local_client(path).await;
		let (addr, _drain_tx) = spawn_admin(
			setup.config.clone(),
			setup.stores.clone(),
			setup.local_client.resource_manager.clone(),
			Some(setup.local_client),
		)
		.await;
		LiveGateway {
			config: setup.config,
			stores: setup.stores,
			metrics: setup.metrics,
			addr,
			_drain_tx,
		}
	}

	#[cfg(feature = "ui")]
	async fn get_json(url: String) -> (reqwest::StatusCode, serde_json::Value) {
		let resp = reqwest::get(url).await.unwrap();
		let status = resp.status();
		let body = resp.text().await.unwrap();
		let value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
		(status, value)
	}

	// Covers the status logic directly so it runs without the ui feature
	#[tokio::test]
	async fn load_status_tracks_reload_success_and_failure() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("alpha"))
			.await
			.unwrap();

		let setup = start_local_client(&path).await;
		wait_for_access_log_remove(&setup.config, &setup.stores, "alpha").await;

		let status = setup.local_client.load_status().await;
		assert_eq!(status.error, None);
		assert!(status.last_updated_at.is_some());
		let applied_hash = status
			.running_hash
			.expect("running hash set after successful load");
		assert!(applied_hash.starts_with("sha256:"));
		assert_eq!(status.disk_hash.as_ref(), Some(&applied_hash));

		fs_err::tokio::write(&path, "{ this is not yaml [")
			.await
			.unwrap();
		wait_for_failed_reload(&setup.metrics).await;

		let status = setup.local_client.load_status().await;
		assert!(status.error.is_some(), "failed reload records an error");
		assert_eq!(
			status.running_hash.as_ref(),
			Some(&applied_hash),
			"running hash keeps the last applied config"
		);
		assert!(
			status.disk_hash.is_some_and(|h| h != applied_hash),
			"disk hash follows the broken file content"
		);
	}

	// A failed reload leaves /api/config serving the never-applied stored file;
	// /api/config/status reports the failure
	#[cfg(feature = "ui")]
	#[tokio::test]
	async fn api_config_returns_unapplied_file_config_after_failed_reload() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("alpha"))
			.await
			.unwrap();

		let gw = start_gateway_with_config_file(&path).await;
		wait_for_access_log_remove(&gw.config, &gw.stores, "alpha").await;

		// While disk and runtime agree, the endpoint reports the applied config
		let resp = reqwest::get(format!("http://{}/api/config", gw.addr))
			.await
			.unwrap();
		assert_eq!(resp.status(), reqwest::StatusCode::OK);
		assert!(resp.text().await.unwrap().contains("alpha"));

		// Valid yaml that fails validation: a bind without a port must set mode: internal
		let broken = r#"
frontendPolicies:
  accessLog:
    remove:
    - beta
binds:
- listeners: []
"#;
		fs_err::tokio::write(&path, broken).await.unwrap();
		wait_for_failed_reload(&gw.metrics).await;

		// The runtime kept the previously applied config
		let frontend = gw
			.stores
			.binds
			.read()
			.frontend_policies(gw.config.gateway_ref());
		assert!(
			frontend
				.access_log
				.as_ref()
				.is_some_and(|access_log| access_log.remove.contains("alpha")),
			"runtime should still run the last successfully applied config"
		);

		// /api/config keeps returning the stored file for backwards compatibility
		let resp = reqwest::get(format!("http://{}/api/config", gw.addr))
			.await
			.unwrap();
		assert_eq!(resp.status(), reqwest::StatusCode::OK);
		let body = resp.text().await.unwrap();
		assert!(
			body.contains("beta") && !body.contains("alpha"),
			"GET /api/config returned the stored file, not the applied config: {body}"
		);

		// /api/config/status reports the failure and the hash mismatch
		let (code, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert!(
			status["error"].is_string(),
			"load error should be reported: {status}"
		);
		assert!(
			status["runningHash"].is_string() && status["diskHash"].is_string(),
			"{status}"
		);
		assert_ne!(
			status["runningHash"], status["diskHash"],
			"running and disk hash should diverge after a failed reload: {status}"
		);
	}

	#[cfg(feature = "ui")]
	#[tokio::test]
	async fn api_config_errors_when_stored_config_is_unparseable() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("alpha"))
			.await
			.unwrap();

		let gw = start_gateway_with_config_file(&path).await;
		wait_for_access_log_remove(&gw.config, &gw.stores, "alpha").await;

		fs_err::tokio::write(&path, "{ this is not yaml [")
			.await
			.unwrap();
		wait_for_failed_reload(&gw.metrics).await;

		// The gateway still runs the old config: /api/config can only 500, while
		// /api/config/status still reports the load state
		let frontend = gw
			.stores
			.binds
			.read()
			.frontend_policies(gw.config.gateway_ref());
		assert!(
			frontend
				.access_log
				.as_ref()
				.is_some_and(|access_log| access_log.remove.contains("alpha")),
			"runtime should still run the last successfully applied config"
		);

		let resp = reqwest::get(format!("http://{}/api/config", gw.addr))
			.await
			.unwrap();
		assert_eq!(
			resp.status(),
			reqwest::StatusCode::INTERNAL_SERVER_ERROR,
			"GET /api/config cannot report anything about the running config once the file is corrupt"
		);

		let (code, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert!(
			status["error"].is_string(),
			"load status must survive a corrupt stored file: {status}"
		);
		assert!(status["runningHash"].is_string(), "{status}");
	}

	#[cfg(feature = "ui")]
	#[tokio::test]
	async fn api_config_status_reports_matching_hashes_when_synced() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("alpha"))
			.await
			.unwrap();

		let gw = start_gateway_with_config_file(&path).await;
		wait_for_access_log_remove(&gw.config, &gw.stores, "alpha").await;

		let (code, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert!(status["error"].is_null(), "{status}");
		assert!(status["lastUpdatedAt"].is_string(), "{status}");
		assert!(
			status["runningHash"]
				.as_str()
				.is_some_and(|h| h.starts_with("sha256:")),
			"{status}"
		);
		assert_eq!(status["runningHash"], status["diskHash"], "{status}");
		let initial_hash = status["runningHash"].clone();

		// A successful reload moves the running hash to the new content. The store
		// is synced before the status is written, so poll for the hash to move.
		fs_err::tokio::write(&path, local_config("gamma"))
			.await
			.unwrap();
		wait_for_access_log_remove(&gw.config, &gw.stores, "gamma").await;

		let status = tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				let (_, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
				if status["runningHash"].is_string() && status["runningHash"] != initial_hash {
					return status;
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("timed out waiting for running hash to advance");
		assert!(status["error"].is_null(), "{status}");
		assert_eq!(status["runningHash"], status["diskHash"], "{status}");
	}

	#[tokio::test]
	async fn file_config_reloads_after_repeated_rename_replacement() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("first"))
			.await
			.unwrap();

		let mut config = test_config();
		config.xds.local_config = Some(ConfigSource::File(path.clone()));
		let config = Arc::new(config);
		let stores = test_stores();
		let mut registry = prometheus_client::registry::Registry::default();
		let metrics = Arc::new(agent_xds::Metrics::new(&mut registry));
		let client = test_client();
		let resource_manager = crate::resource_manager::ResourceManager::new(client.clone()).unwrap();
		let local_client = LocalClient {
			config: config.clone(),
			cfg: ConfigSource::File(path.clone()),
			stores: stores.clone(),
			client,
			resource_manager,
			gateway: config.gateway(),
			metrics,
			status: Default::default(),
		};

		local_client.run().await.unwrap();
		wait_for_access_log_remove(&config, &stores, "first").await;

		fs_err::tokio::write(&path, local_config("ready"))
			.await
			.unwrap();
		wait_for_access_log_remove(&config, &stores, "ready").await;

		replace_config(&path, "second").await;
		wait_for_access_log_remove(&config, &stores, "second").await;

		fs_err::tokio::write(&path, local_config("ready-again"))
			.await
			.unwrap();
		wait_for_access_log_remove(&config, &stores, "ready-again").await;

		replace_config(&path, "third").await;
		wait_for_access_log_remove(&config, &stores, "third").await;
	}
}
