//! Bounded admission for authenticated local IPC doors.
//!
//! A connection first holds a short-lived handshake permit, keyed by the kernel peer uid.  Once
//! Noise has authenticated the component it swaps that permit for an active permit keyed by the
//! component's public key.  Both permits are RAII values: cancellation, protocol errors and EOF
//! return capacity without a separate cleanup path.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionLimits {
    pub handshakes: usize,
    pub handshakes_per_peer: usize,
    pub active: usize,
    pub active_per_principal: usize,
}

impl AdmissionLimits {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.handshakes == 0 || self.active == 0 {
            return Err("global IPC limits must be non-zero");
        }
        if self.handshakes_per_peer == 0 || self.handshakes_per_peer > self.handshakes {
            return Err("per-peer handshake limit must be within the global limit");
        }
        if self.active_per_principal == 0 || self.active_per_principal > self.active {
            return Err("per-principal active limit must be within the global limit");
        }
        Ok(self)
    }
}

struct Pool {
    total: Arc<Semaphore>,
    per_principal: usize,
    principals: Mutex<HashMap<Vec<u8>, Weak<Semaphore>>>,
}

impl Pool {
    fn new(total: usize, per_principal: usize) -> Pool {
        Pool { total: Arc::new(Semaphore::new(total)), per_principal, principals: Mutex::new(HashMap::new()) }
    }

    fn principal(&self, id: &[u8]) -> Arc<Semaphore> {
        let mut principals = self.principals.lock().unwrap();
        if principals.len() > 256 {
            principals.retain(|_, semaphore| semaphore.strong_count() > 0);
        }
        if let Some(semaphore) = principals.get(id).and_then(Weak::upgrade) {
            return semaphore;
        }
        let semaphore = Arc::new(Semaphore::new(self.per_principal));
        principals.insert(id.to_vec(), Arc::downgrade(&semaphore));
        semaphore
    }

    fn try_acquire(&self, principal: &[u8]) -> Option<IpcPermit> {
        // Take the principal share first so a saturated principal cannot reserve global capacity.
        let principal = self.principal(principal).try_acquire_owned().ok()?;
        let total = self.total.clone().try_acquire_owned().ok()?;
        Some(IpcPermit { _total: total, _principal: principal })
    }
}

#[derive(Clone)]
pub struct IpcAdmission {
    handshakes: Arc<Pool>,
    active: Arc<Pool>,
}

impl IpcAdmission {
    pub fn new(limits: AdmissionLimits) -> IpcAdmission {
        let limits = limits.validate().expect("invalid built-in IPC admission limits");
        IpcAdmission {
            handshakes: Arc::new(Pool::new(limits.handshakes, limits.handshakes_per_peer)),
            active: Arc::new(Pool::new(limits.active, limits.active_per_principal)),
        }
    }

    pub fn try_handshake(&self, peer_uid: u32) -> Option<IpcPermit> {
        self.handshakes.try_acquire(&peer_uid.to_be_bytes())
    }

    pub fn try_active(&self, authenticated_principal: &[u8]) -> Option<IpcPermit> {
        self.active.try_acquire(authenticated_principal)
    }
}

pub struct IpcPermit {
    _total: OwnedSemaphorePermit,
    _principal: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_cannot_monopolize_and_raii_releases_both_levels() {
        let admission = IpcAdmission::new(AdmissionLimits { handshakes: 2, handshakes_per_peer: 1, active: 3, active_per_principal: 2 });
        let a1 = admission.try_active(b"a").unwrap();
        let a2 = admission.try_active(b"a").unwrap();
        assert!(admission.try_active(b"a").is_none());
        let b = admission.try_active(b"b").unwrap();
        assert!(admission.try_active(b"c").is_none());
        drop(a1);
        assert!(admission.try_active(b"c").is_some());
        drop((a2, b));
        assert!(admission.try_active(b"a").is_some());
    }

    #[test]
    fn stalled_handshakes_are_bounded_per_kernel_peer() {
        let admission = IpcAdmission::new(AdmissionLimits { handshakes: 3, handshakes_per_peer: 2, active: 1, active_per_principal: 1 });
        let _a1 = admission.try_handshake(10).unwrap();
        let _a2 = admission.try_handshake(10).unwrap();
        assert!(admission.try_handshake(10).is_none());
        let b = admission.try_handshake(11).unwrap();
        assert!(admission.try_handshake(12).is_none());
        drop(b);
        assert!(admission.try_handshake(12).is_some());
    }
}
