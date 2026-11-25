//! Failed-login memory per key and per address: after `lock_after` failures further attempts are refused (without even checking the password) for a time that doubles with every failure, up to `lock_max`.
//! A success clears the record. The table is bounded.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 4096;

pub struct Throttle {
    lock_after: u32,
    lock_base: Duration,
    lock_max: Duration,
    map: Mutex<HashMap<String, (u32, Instant)>>,
}

impl Throttle {
    pub fn new(lock_after: u32, lock_base: Duration, lock_max: Duration) -> Throttle {
        Throttle { lock_after, lock_base, lock_max, map: Mutex::new(HashMap::new()) }
    }
    pub fn locked(&self, key: &str) -> bool {
        self.map.lock().unwrap().get(key).is_some_and(|(_, until)| Instant::now() < *until)
    }
    pub fn fail(&self, key: &str) {
        let mut m = self.map.lock().unwrap();
        if m.len() >= MAX_ENTRIES && !m.contains_key(key) {
            let now = Instant::now();
            m.retain(|_, (_, until)| now < *until); // forget the expired ones
            if m.len() >= MAX_ENTRIES {
                return; // full of live locks: the new one is not recorded, the table never grows
            }
        }
        let e = m.entry(key.to_string()).or_insert((0, Instant::now()));
        e.0 = e.0.saturating_add(1);
        if e.0 >= self.lock_after {
            let doublings = (e.0 - self.lock_after).min(20);
            let wait = self.lock_base.saturating_mul(1u32 << doublings).min(self.lock_max);
            e.1 = Instant::now() + wait;
        }
    }
    pub fn ok(&self, key: &str) {
        self.map.lock().unwrap().remove(key);
    }
}

impl Throttle {
    /// how many keys are remembered (never more than the fixed bound)
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
