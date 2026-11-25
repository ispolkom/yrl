//! Process-wide resource admission for Executor sessions.
//!
//! Link bytes use asynchronous semaphores: a producer waits (backpressure) instead of dropping a
//! frame. Operation admission is deliberately non-blocking, matching the existing per-session
//! limits: an overloaded request receives the ordinary "too many requests" error.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub link_bytes_total: usize,
    pub link_bytes_per_key: usize,
    pub link_bytes_per_account: usize,
    pub max_operations_total: usize,
    pub max_operations_per_session: usize,
    pub max_operations_per_key: usize,
    pub max_operations_per_account: usize,
    pub max_exec_total: usize,
    pub max_pty_total: usize,
    pub max_transfers_total: usize,
    pub max_tunnels_total: usize,
    pub max_fs_total: usize,
    pub max_network_connections_total: usize,
    pub max_network_connections_per_key: usize,
    pub max_network_connections_per_account: usize,
    /// Bytes written by one session before a waiting session gets a turn. This is fairness, not a rate.
    pub network_write_quantum: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            link_bytes_total: 256 << 20,
            link_bytes_per_key: 64 << 20,
            link_bytes_per_account: 64 << 20,
            max_operations_total: 256,
            max_operations_per_session: 32,
            max_operations_per_key: 64,
            max_operations_per_account: 64,
            max_exec_total: 64,
            max_pty_total: 32,
            max_transfers_total: 32,
            max_tunnels_total: 128,
            max_fs_total: 64,
            max_network_connections_total: 256,
            // Twice the default session share permits a replacement route to attach before the
            // superseded transport has observed EOF and released its permit.
            max_network_connections_per_key: 32,
            max_network_connections_per_account: 32,
            network_write_quantum: 16 << 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum OperationKind {
    Exec,
    Pty,
    Transfer,
    Tunnel,
    Fs,
}

impl ResourceLimits {
    pub fn from_env() -> anyhow::Result<ResourceLimits> {
        fn value(name: &str, default: usize) -> anyhow::Result<usize> {
            match std::env::var(name) {
                Ok(v) => v.parse::<usize>().map_err(|_| anyhow::anyhow!("invalid {name}")),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(_) => Err(anyhow::anyhow!("invalid {name}")),
            }
        }
        let mut limits = ResourceLimits::default();
        limits.max_network_connections_total = value("YRL_NETWORK_CONNECTIONS_TOTAL", limits.max_network_connections_total)?;
        limits.max_network_connections_per_key = value("YRL_NETWORK_CONNECTIONS_PER_KEY", limits.max_network_connections_per_key)?;
        limits.max_network_connections_per_account = value("YRL_NETWORK_CONNECTIONS_PER_ACCOUNT", limits.max_network_connections_per_account)?;
        limits.network_write_quantum = value("YRL_NETWORK_QUANTUM_BYTES", limits.network_write_quantum)?;
        limits.validate().map_err(|e| anyhow::anyhow!(e))?;
        Ok(limits)
    }

    fn operation_limit(&self, kind: OperationKind) -> usize {
        match kind {
            OperationKind::Exec => self.max_exec_total,
            OperationKind::Pty => self.max_pty_total,
            OperationKind::Transfer => self.max_transfers_total,
            OperationKind::Tunnel => self.max_tunnels_total,
            OperationKind::Fs => self.max_fs_total,
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        let memory = [
            self.link_bytes_total,
            self.link_bytes_per_key,
            self.link_bytes_per_account,
        ];
        if memory.iter().any(|n| *n < crate::wire::MAX_FRAME) {
            return Err("every Link memory limit must hold one maximum-size frame");
        }
        if memory.iter().any(|n| *n > u32::MAX as usize) {
            return Err("Link memory limits must fit the semaphore counter");
        }
        let operations = [
            self.max_operations_total,
            self.max_operations_per_session,
            self.max_operations_per_key,
            self.max_operations_per_account,
            self.max_exec_total,
            self.max_pty_total,
            self.max_transfers_total,
            self.max_tunnels_total,
            self.max_fs_total,
        ];
        if operations.contains(&0) {
            return Err("operation limits must be non-zero");
        }
        if self.max_network_connections_total == 0
            || self.max_network_connections_per_key == 0
            || self.max_network_connections_per_account == 0
            || self.max_network_connections_per_key > self.max_network_connections_total
            || self.max_network_connections_per_account > self.max_network_connections_total
        {
            return Err("network connection limits must be non-zero and within the global limit");
        }
        if self.network_write_quantum == 0 || self.network_write_quantum > crate::wire::MAX_FRAME {
            return Err("network write quantum must be between one byte and one maximum frame");
        }
        Ok(())
    }
}

#[derive(Default)]
struct Counts {
    sessions: usize,
    sessions_by_key: HashMap<Vec<u8>, usize>,
    sessions_by_account: HashMap<String, usize>,
    operations: usize,
    operations_by_session: HashMap<u64, usize>,
    operations_by_key: HashMap<Vec<u8>, usize>,
    operations_by_account: HashMap<String, usize>,
    operations_by_kind: HashMap<OperationKind, usize>,
    network_connections: usize,
    network_by_key: HashMap<Vec<u8>, usize>,
    network_by_account: HashMap<String, usize>,
}

pub struct ResourceManager {
    limits: ResourceLimits,
    link_total: Arc<MemoryPool>,
    link_keys: Mutex<HashMap<Vec<u8>, Weak<MemoryPool>>>,
    link_accounts: Mutex<HashMap<String, Weak<MemoryPool>>>,
    counts: Mutex<Counts>,
    network: Arc<crate::network::FairNetwork>,
    next_network_flow: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceUsage {
    pub link_bytes: usize,
    pub sessions: usize,
    pub operations: usize,
    pub network_connections: usize,
}

impl Default for ResourceManager {
    fn default() -> Self {
        ResourceManager::new(ResourceLimits::default()).expect("default resource limits are valid")
    }
}

impl ResourceManager {
    pub fn new(limits: ResourceLimits) -> Result<Self, &'static str> {
        limits.validate()?;
        let network = crate::network::FairNetwork::new(limits.network_write_quantum);
        Ok(ResourceManager {
            link_total: Arc::new(MemoryPool::new(limits.link_bytes_total)),
            limits,
            link_keys: Mutex::new(HashMap::new()),
            link_accounts: Mutex::new(HashMap::new()),
            counts: Mutex::new(Counts::default()),
            network,
            next_network_flow: AtomicU64::new(1),
        })
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn usage(&self) -> ResourceUsage {
        let c = self.counts.lock().unwrap();
        ResourceUsage {
            link_bytes: self.limits.link_bytes_total - self.link_total.all.available_permits(),
            sessions: c.sessions,
            operations: c.operations,
            network_connections: c.network_connections,
        }
    }

    fn key_memory(&self, key: &[u8]) -> Arc<MemoryPool> {
        let mut sems = self.link_keys.lock().unwrap();
        if let Some(s) = sems.get(key).and_then(Weak::upgrade) {
            return s;
        }
        sems.retain(|_, s| s.strong_count() != 0);
        let s = Arc::new(MemoryPool::new(self.limits.link_bytes_per_key));
        sems.insert(key.to_vec(), Arc::downgrade(&s));
        s
    }

    fn account_memory(&self, account: &str) -> Arc<MemoryPool> {
        let mut sems = self.link_accounts.lock().unwrap();
        if let Some(s) = sems.get(account).and_then(Weak::upgrade) {
            return s;
        }
        sems.retain(|_, s| s.strong_count() != 0);
        let s = Arc::new(MemoryPool::new(self.limits.link_bytes_per_account));
        sems.insert(account.to_string(), Arc::downgrade(&s));
        s
    }

    pub fn try_session(
        self: &Arc<Self>,
        key: &[u8],
        account: &str,
        max_sessions: usize,
        max_sessions_per_key: usize,
        max_sessions_per_account: usize,
    ) -> Option<SessionPermit> {
        let mut c = self.counts.lock().unwrap();
        if c.sessions >= max_sessions
            || c.sessions_by_key.get(key).copied().unwrap_or(0) >= max_sessions_per_key
            || c.sessions_by_account.get(account).copied().unwrap_or(0) >= max_sessions_per_account
        {
            return None;
        }
        c.sessions += 1;
        *c.sessions_by_key.entry(key.to_vec()).or_default() += 1;
        *c.sessions_by_account
            .entry(account.to_string())
            .or_default() += 1;
        drop(c);
        Some(SessionPermit {
            manager: self.clone(),
            key: key.to_vec(),
            account: account.to_string(),
            link: LinkBudget {
                total: self.link_total.clone(),
                key: self.key_memory(key),
                account: self.account_memory(account),
            },
        })
    }

    pub fn try_operation(
        self: &Arc<Self>,
        session: u64,
        key: &[u8],
        account: &str,
        kind: OperationKind,
    ) -> Option<OperationPermit> {
        let mut c = self.counts.lock().unwrap();
        if c.operations >= self.limits.max_operations_total
            || c.operations_by_session.get(&session).copied().unwrap_or(0)
                >= self.limits.max_operations_per_session
            || c.operations_by_key.get(key).copied().unwrap_or(0)
                >= self.limits.max_operations_per_key
            || c.operations_by_account.get(account).copied().unwrap_or(0)
                >= self.limits.max_operations_per_account
            || c.operations_by_kind.get(&kind).copied().unwrap_or(0)
                >= self.limits.operation_limit(kind)
        {
            return None;
        }
        c.operations += 1;
        *c.operations_by_session.entry(session).or_default() += 1;
        *c.operations_by_key.entry(key.to_vec()).or_default() += 1;
        *c.operations_by_account
            .entry(account.to_string())
            .or_default() += 1;
        *c.operations_by_kind.entry(kind).or_default() += 1;
        drop(c);
        Some(OperationPermit {
            manager: self.clone(),
            session,
            key: key.to_vec(),
            account: account.to_string(),
            kind,
        })
    }

    /// Admission for one currently attached authenticated transport. The session may outlive it;
    /// dropping this permit on EOF/cancellation releases all network counters for RESUME.
    pub fn try_network_connection(self: &Arc<Self>, key: &[u8], account: &str) -> Option<NetworkConnectionPermit> {
        let mut c = self.counts.lock().unwrap();
        if c.network_connections >= self.limits.max_network_connections_total
            || c.network_by_key.get(key).copied().unwrap_or(0) >= self.limits.max_network_connections_per_key
            || c.network_by_account.get(account).copied().unwrap_or(0) >= self.limits.max_network_connections_per_account
        {
            return None;
        }
        c.network_connections += 1;
        *c.network_by_key.entry(key.to_vec()).or_default() += 1;
        *c.network_by_account.entry(account.to_string()).or_default() += 1;
        drop(c);
        let id = self.next_network_flow.fetch_add(1, Ordering::Relaxed);
        Some(NetworkConnectionPermit {
            manager: self.clone(),
            key: key.to_vec(),
            account: account.to_string(),
            flow: self.network.flow(id),
        })
    }
}

pub struct SessionPermit {
    manager: Arc<ResourceManager>,
    key: Vec<u8>,
    account: String,
    link: LinkBudget,
}

impl SessionPermit {
    pub fn link_budget(&self) -> LinkBudget {
        self.link.clone()
    }
}

fn decrement<K: std::hash::Hash + Eq>(map: &mut HashMap<K, usize>, key: &K) {
    if let Some(n) = map.get_mut(key) {
        *n -= 1;
        if *n == 0 {
            map.remove(key);
        }
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        let mut c = self.manager.counts.lock().unwrap();
        c.sessions -= 1;
        decrement(&mut c.sessions_by_key, &self.key);
        decrement(&mut c.sessions_by_account, &self.account);
    }
}

pub struct OperationPermit {
    manager: Arc<ResourceManager>,
    session: u64,
    key: Vec<u8>,
    account: String,
    kind: OperationKind,
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        let mut c = self.manager.counts.lock().unwrap();
        c.operations -= 1;
        decrement(&mut c.operations_by_session, &self.session);
        decrement(&mut c.operations_by_key, &self.key);
        decrement(&mut c.operations_by_account, &self.account);
        decrement(&mut c.operations_by_kind, &self.kind);
    }
}

pub struct NetworkConnectionPermit {
    manager: Arc<ResourceManager>,
    key: Vec<u8>,
    account: String,
    flow: crate::network::NetworkFlow,
}

impl NetworkConnectionPermit {
    pub fn flow(&self) -> crate::network::NetworkFlow {
        self.flow.clone()
    }
}

impl Drop for NetworkConnectionPermit {
    fn drop(&mut self) {
        let mut c = self.manager.counts.lock().unwrap();
        c.network_connections -= 1;
        decrement(&mut c.network_by_key, &self.key);
        decrement(&mut c.network_by_account, &self.account);
    }
}

#[derive(Clone)]
pub struct LinkBudget {
    total: Arc<MemoryPool>,
    key: Arc<MemoryPool>,
    account: Arc<MemoryPool>,
}

pub struct LinkMemoryPermit {
    _permits: Vec<OwnedSemaphorePermit>,
}

struct MemoryPool {
    all: Arc<Semaphore>,
    non_interactive: Arc<Semaphore>,
}

impl MemoryPool {
    fn new(capacity: usize) -> Self {
        let wanted_reserve = (capacity / 8).min(256 << 10);
        let reserve = wanted_reserve.min(capacity.saturating_sub(crate::wire::MAX_FRAME));
        MemoryPool {
            all: Arc::new(Semaphore::new(capacity)),
            non_interactive: Arc::new(Semaphore::new(capacity - reserve)),
        }
    }
}

impl LinkBudget {
    pub async fn reserve(&self, bytes: usize, interactive: bool) -> Result<LinkMemoryPermit, ()> {
        let n = u32::try_from(bytes).map_err(|_| ())?;
        // Principal quotas are acquired before the shared pool, so a principal waiting for its own
        // quota never occupies capacity that another key/account could use. Non-interactive frames
        // also pass through smaller pools, preserving room for control and terminal traffic without
        // increasing any configured memory ceiling.
        let mut permits = Vec::with_capacity(if interactive { 3 } else { 6 });
        if !interactive {
            permits.push(
                self.key
                    .non_interactive
                    .clone()
                    .acquire_many_owned(n)
                    .await
                    .map_err(|_| ())?,
            );
            permits.push(
                self.account
                    .non_interactive
                    .clone()
                    .acquire_many_owned(n)
                    .await
                    .map_err(|_| ())?,
            );
            permits.push(
                self.total
                    .non_interactive
                    .clone()
                    .acquire_many_owned(n)
                    .await
                    .map_err(|_| ())?,
            );
        }
        permits.push(
            self.key
                .all
                .clone()
                .acquire_many_owned(n)
                .await
                .map_err(|_| ())?,
        );
        permits.push(
            self.account
                .all
                .clone()
                .acquire_many_owned(n)
                .await
                .map_err(|_| ())?,
        );
        permits.push(
            self.total
                .all
                .clone()
                .acquire_many_owned(n)
                .await
                .map_err(|_| ())?,
        );
        Ok(LinkMemoryPermit { _permits: permits })
    }
}
