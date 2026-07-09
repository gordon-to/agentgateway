use serde::Serialize;

use crate::ConfigSource;

/// Creates the config load status channel. The publisher records load attempts
/// from the local config loader; the watcher serves status snapshots to the
/// admin and UI endpoints. When `enabled` is false (no local config), the
/// watcher permanently reports no status.
// xds nacks (RejectedConfig) are load failures too; a publisher in the xds
// client can feed this same channel to surface them beyond control plane logs.
pub fn channel(enabled: bool) -> (Publisher, Watcher) {
	let snapshot = if enabled {
		Snapshot::Enabled(Inner::default())
	} else {
		Snapshot::Disabled
	};
	let (tx, rx) = tokio::sync::watch::channel(snapshot);
	(Publisher { tx }, Watcher { rx })
}

#[derive(Debug)]
enum Snapshot {
	Disabled,
	Enabled(Inner),
}

#[derive(Debug, Clone, Default)]
struct Inner {
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
	at: chrono::DateTime<chrono::Utc>,
	error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
	Synced,
	Drifted,
	Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
	state: State,
	applied_generation: Option<u64>,
	applied_at: Option<chrono::DateTime<chrono::Utc>>,
	applied_hash: Option<String>,
	last_attempt: Option<Attempt>,
	stored_matches_applied: bool,
}

/// Publisher records the outcome of local config load attempts.
#[derive(Debug, Clone)]
pub struct Publisher {
	tx: tokio::sync::watch::Sender<Snapshot>,
}

impl Publisher {
	pub fn success(&self, raw: String) {
		use sha2::Digest as _;
		let at = chrono::Utc::now();
		let hash = format!(
			"sha256:{}",
			hex::encode(sha2::Sha256::digest(raw.as_bytes()))
		);
		self.tx.send_modify(|snapshot| {
			let Snapshot::Enabled(inner) = snapshot else {
				return;
			};
			let generation = inner.applied.as_ref().map_or(0, |a| a.generation) + 1;
			inner.applied = Some(Applied {
				raw,
				generation,
				at,
				hash,
			});
			inner.last_attempt = Some(Attempt { at, error: None });
		});
	}

	pub fn failure(&self, error: String) {
		self.tx.send_modify(|snapshot| {
			let Snapshot::Enabled(inner) = snapshot else {
				return;
			};
			inner.last_attempt = Some(Attempt {
				at: chrono::Utc::now(),
				error: Some(error),
			});
		});
	}
}

/// Watcher reads the load status snapshots published by the local config loader.
#[derive(Debug, Clone)]
pub struct Watcher {
	rx: tokio::sync::watch::Receiver<Snapshot>,
}

impl Watcher {
	/// Returns the last successfully applied raw config and the load status as
	/// one consistent snapshot, or None when no local config is set up.
	pub async fn live(&self, cfg: &ConfigSource) -> Option<(Option<String>, Status)> {
		let inner = match &*self.rx.borrow() {
			Snapshot::Disabled => return None,
			Snapshot::Enabled(inner) => inner.clone(),
		};
		let stored_matches_applied = match &inner.applied {
			Some(applied) => match cfg.read_to_string().await {
				Ok(stored) => equivalent(&applied.raw, &stored),
				Err(_) => false,
			},
			None => false,
		};
		let failed = inner
			.last_attempt
			.as_ref()
			.is_some_and(|a| a.error.is_some());
		let state = if failed {
			State::Failed
		} else if stored_matches_applied {
			State::Synced
		} else {
			State::Drifted
		};
		let status = Status {
			state,
			applied_generation: inner.applied.as_ref().map(|a| a.generation),
			applied_at: inner.applied.as_ref().map(|a| a.at),
			applied_hash: inner.applied.as_ref().map(|a| a.hash.clone()),
			last_attempt: inner.last_attempt,
			stored_matches_applied,
		};
		Some((inner.applied.map(|a| a.raw), status))
	}

	pub async fn status(&self, cfg: &ConfigSource) -> Option<Status> {
		Some(self.live(cfg).await?.1)
	}
}

// compares configs by parsed value so formatting and comments don't count as drift
fn equivalent(a: &str, b: &str) -> bool {
	let parse = |s: &str| crate::yamlviajson::from_str::<serde_json::Value>(s).ok();
	match (parse(a), parse(b)) {
		(Some(a), Some(b)) => a == b,
		_ => false,
	}
}
