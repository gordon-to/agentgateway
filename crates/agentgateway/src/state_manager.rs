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
	local_config_status: Option<LoadStatus>,
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
		let mut local_config_status = None;
		if let Some(cfg) = &xds.local_config {
			let status = LoadStatus::default();
			local_config_status = Some(status.clone());
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
				status,
			};
			Box::pin(local_client.run()).await?;
		}
		Ok(Self {
			stores,
			xds_client,
			resource_manager,
			local_config_status,
		})
	}

	pub fn stores(&self) -> Stores {
		self.stores.clone()
	}

	pub fn resource_manager(&self) -> crate::resource_manager::ResourceManager {
		self.resource_manager.clone()
	}

	pub fn local_config_status(&self) -> Option<LoadStatus> {
		self.local_config_status.clone()
	}

	pub async fn run(self) -> anyhow::Result<()> {
		match self.xds_client {
			Some(xds) => xds.run().await.map_err(|e| anyhow::anyhow!(e)),
			None => Ok(()),
		}
	}
}

/// LoadStatus tracks the outcome of local config load attempts: the raw config
/// that was last successfully applied and the result of the most recent attempt.
/// It is shared between the loader and the admin/UI endpoints that report it.
#[derive(Debug, Clone, Default)]
pub struct LoadStatus {
	inner: Arc<std::sync::RwLock<LoadStatusInner>>,
}

#[derive(Debug, Default)]
struct LoadStatusInner {
	applied: Option<Applied>,
	last_attempt: Option<Attempt>,
}

#[derive(Debug, Clone)]
struct Applied {
	raw: String,
	generation: u64,
	at: chrono::DateTime<chrono::Utc>,
	hash: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
	at: chrono::DateTime<chrono::Utc>,
	error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoadState {
	Synced,
	Drifted,
	Failed,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
	state: LoadState,
	applied_generation: Option<u64>,
	applied_at: Option<chrono::DateTime<chrono::Utc>>,
	applied_hash: Option<String>,
	last_attempt: Option<Attempt>,
	stored_matches_applied: bool,
}

impl LoadStatus {
	fn record_success(&self, raw: String) {
		use sha2::Digest as _;
		let at = chrono::Utc::now();
		let hash = format!(
			"sha256:{}",
			hex::encode(sha2::Sha256::digest(raw.as_bytes()))
		);
		let mut inner = self.inner.write().expect("mutex acquired");
		let generation = inner.applied.as_ref().map_or(0, |a| a.generation) + 1;
		inner.applied = Some(Applied {
			raw,
			generation,
			at,
			hash,
		});
		inner.last_attempt = Some(Attempt { at, error: None });
	}

	fn record_failure(&self, error: String) {
		let mut inner = self.inner.write().expect("mutex acquired");
		inner.last_attempt = Some(Attempt {
			at: chrono::Utc::now(),
			error: Some(error),
		});
	}

	/// Returns the last successfully applied raw config and the load status as
	/// one consistent snapshot.
	pub async fn live(&self, cfg: &ConfigSource) -> (Option<String>, Status) {
		let (applied, last_attempt) = {
			let inner = self.inner.read().expect("mutex acquired");
			(inner.applied.clone(), inner.last_attempt.clone())
		};
		let stored_matches_applied = match &applied {
			Some(applied) => match cfg.read_to_string().await {
				Ok(stored) => config_equivalent(&applied.raw, &stored),
				Err(_) => false,
			},
			None => false,
		};
		let failed = last_attempt.as_ref().is_some_and(|a| a.error.is_some());
		let state = if failed {
			LoadState::Failed
		} else if stored_matches_applied {
			LoadState::Synced
		} else {
			LoadState::Drifted
		};
		let status = Status {
			state,
			applied_generation: applied.as_ref().map(|a| a.generation),
			applied_at: applied.as_ref().map(|a| a.at),
			applied_hash: applied.as_ref().map(|a| a.hash.clone()),
			last_attempt,
			stored_matches_applied,
		};
		(applied.map(|a| a.raw), status)
	}

	pub async fn status(&self, cfg: &ConfigSource) -> Status {
		self.live(cfg).await.1
	}
}

// compares configs by parsed value so formatting and comments don't count as drift
fn config_equivalent(a: &str, b: &str) -> bool {
	let parse = |s: &str| crate::yamlviajson::from_str::<serde_json::Value>(s).ok();
	match (parse(a), parse(b)) {
		(Some(a), Some(b)) => a == b,
		_ => false,
	}
}

/// LocalClient serves as a local file reader alternative for XDS. This is intended for testing.
#[derive(Debug, Clone)]
pub struct LocalClient {
	config: Arc<crate::Config>,
	pub cfg: ConfigSource,
	pub stores: Stores,
	pub client: Client,
	pub resource_manager: crate::resource_manager::ResourceManager,
	pub gateway: ListenerTarget,
	pub metrics: Arc<agent_xds::Metrics>,
	status: LoadStatus,
}

impl LocalClient {
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

		self.status.record_success(config_content);

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
				// record before the gauge flips so observers of the metric see the error
				self.status.record_failure(format!("{e:#}"));
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
		local_config_status: Option<LoadStatus>,
	) -> (std::net::SocketAddr, agent_core::drain::DrainTrigger) {
		let shutdown = agent_core::signal::Shutdown::new();
		let (drain_tx, drain_rx) = agent_core::drain::new();
		let svc = crate::management::admin::Service::new(
			config,
			crate::llm::cost::ModelCatalog::empty(),
			stores,
			resource_manager,
			local_config_status,
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

	#[cfg(feature = "ui")]
	async fn wait_for_failed_reload(metrics: &agent_xds::Metrics) {
		tokio::time::timeout(Duration::from_secs(5), async {
			while metrics.config_synchronized.get() != 0 {
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("timed out waiting for reload failure");
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
		let status = LoadStatus::default();
		let local_client = LocalClient {
			config: config.clone(),
			cfg: ConfigSource::File(path.to_path_buf()),
			stores: stores.clone(),
			client,
			resource_manager: resource_manager.clone(),
			gateway: config.gateway(),
			metrics: metrics.clone(),
			status: status.clone(),
		};
		local_client.run().await.expect("initial config load");
		let (addr, _drain_tx) = spawn_admin(
			config.clone(),
			stores.clone(),
			resource_manager,
			Some(status),
		)
		.await;
		LiveGateway {
			config,
			stores,
			metrics,
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

	// GET /api/config returns the stored config file, byte-compatible with older
	// releases, even when that file was never applied. the applied config and load
	// state are exposed additively on /api/config/live and /api/config/status.
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

		// while disk and runtime agree, the endpoint reports the applied config
		let resp = reqwest::get(format!("http://{}/api/config", gw.addr))
			.await
			.unwrap();
		assert_eq!(resp.status(), reqwest::StatusCode::OK);
		assert!(resp.text().await.unwrap().contains("alpha"));

		// valid yaml that fails validation: a bind without a port must set mode: internal
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

		// the runtime kept the previously applied config
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

		// /api/config/live reports the applied config plus the failure
		let (code, live) = get_json(format!("http://{}/api/config/live", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert_eq!(
			live["config"]["frontendPolicies"]["accessLog"]["remove"][0], "alpha",
			"live config should be the applied config: {live}"
		);
		assert_eq!(live["status"]["state"], "failed", "{live}");
		assert_eq!(live["status"]["storedMatchesApplied"], false, "{live}");
		assert_eq!(live["status"]["appliedGeneration"], 1, "{live}");
		assert!(
			live["status"]["lastAttempt"]["error"].is_string(),
			"load error should be reported: {live}"
		);

		// /api/config/status reports the same status standalone
		let (code, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert_eq!(status["state"], "failed", "{status}");

		// /config_dump includes the load status additively
		let (code, dump) = get_json(format!("http://{}/config_dump", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert_eq!(dump["localConfigStatus"]["state"], "failed", "{dump}");
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

		// the gateway still runs the old config; /api/config can only 500 (kept
		// for compatibility), while /api/config/live still serves the applied config
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

		let (code, live) = get_json(format!("http://{}/api/config/live", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert_eq!(
			live["config"]["frontendPolicies"]["accessLog"]["remove"][0], "alpha",
			"live config must survive a corrupt stored file: {live}"
		);
		assert_eq!(live["status"]["state"], "failed", "{live}");
	}

	#[cfg(feature = "ui")]
	#[tokio::test]
	async fn api_config_status_reports_synced_and_tracks_generations() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("alpha"))
			.await
			.unwrap();

		let gw = start_gateway_with_config_file(&path).await;
		wait_for_access_log_remove(&gw.config, &gw.stores, "alpha").await;

		let (code, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert_eq!(status["state"], "synced", "{status}");
		assert_eq!(status["storedMatchesApplied"], true, "{status}");
		assert_eq!(status["appliedGeneration"], 1, "{status}");
		assert!(status["appliedAt"].is_string(), "{status}");
		assert!(
			status["appliedHash"]
				.as_str()
				.is_some_and(|h| h.starts_with("sha256:")),
			"{status}"
		);
		assert!(status["lastAttempt"]["error"].is_null(), "{status}");

		// a successful reload bumps the generation and stays synced. the store is
		// synced before the status is recorded, and the watcher may observe a
		// single write as more than one event, so poll for the advanced generation.
		fs_err::tokio::write(&path, local_config("gamma"))
			.await
			.unwrap();
		wait_for_access_log_remove(&gw.config, &gw.stores, "gamma").await;

		let status = tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				let (_, status) = get_json(format!("http://{}/api/config/status", gw.addr)).await;
				if status["appliedGeneration"].as_u64().is_some_and(|g| g >= 2) {
					return status;
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("timed out waiting for applied generation to advance");
		assert_eq!(status["state"], "synced", "{status}");

		let (code, live) = get_json(format!("http://{}/api/config/live", gw.addr)).await;
		assert_eq!(code, reqwest::StatusCode::OK);
		assert_eq!(
			live["config"]["frontendPolicies"]["accessLog"]["remove"][0], "gamma",
			"{live}"
		);
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
			status: LoadStatus::default(),
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
