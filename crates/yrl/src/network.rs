//! Work-conserving network fairness.
//!
//! A flow may write one configurable quantum and then yields to another waiting flow.  There is no
//! clock and no token rate: with no contention acquisition is immediate, so this mechanism cannot
//! impose an artificial bandwidth ceiling.  Interactive/control turns have a protected lane, with
//! a bounded burst so sustained control traffic cannot starve normal data forever.
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

const INTERACTIVE_BURST: u8 = 8;

#[derive(Default)]
struct FlowWaiters {
    interactive: VecDeque<oneshot::Sender<()>>,
    normal: VecDeque<oneshot::Sender<()>>,
}

#[derive(Default)]
struct State {
    owned: bool,
    last_flow: Option<u64>,
    interactive_burst: u8,
    interactive: VecDeque<u64>,
    normal: VecDeque<u64>,
    waiters: HashMap<u64, FlowWaiters>,
}

pub struct FairNetwork {
    quantum: usize,
    state: Mutex<State>,
}

impl FairNetwork {
    pub fn new(quantum: usize) -> Arc<FairNetwork> {
        assert!(quantum > 0, "network fairness quantum must be non-zero");
        Arc::new(FairNetwork { quantum, state: Mutex::new(State::default()) })
    }

    pub fn flow(self: &Arc<Self>, id: u64) -> NetworkFlow {
        NetworkFlow { scheduler: self.clone(), id }
    }

    fn enqueue(st: &mut State, id: u64, interactive: bool, tx: oneshot::Sender<()>) {
        let waiters = st.waiters.entry(id).or_default();
        let queue = if interactive { &mut waiters.interactive } else { &mut waiters.normal };
        if queue.is_empty() {
            if interactive { st.interactive.push_back(id) } else { st.normal.push_back(id) };
        }
        queue.push_back(tx);
    }

    fn pop_flow(order: &mut VecDeque<u64>, last: Option<u64>) -> Option<u64> {
        if order.len() > 1 && order.front().copied() == last {
            let id = order.pop_front().unwrap();
            order.push_back(id);
        }
        order.pop_front()
    }

    fn grant_next(&self) {
        let mut st = self.state.lock().unwrap();
        loop {
            let interactive = !st.interactive.is_empty() && (st.normal.is_empty() || st.interactive_burst < INTERACTIVE_BURST);
            let last = st.last_flow;
            let id = if interactive {
                Self::pop_flow(&mut st.interactive, last)
            } else {
                Self::pop_flow(&mut st.normal, last)
            };
            let Some(id) = id else {
                st.owned = false;
                st.interactive_burst = 0;
                return;
            };
            let Some((tx, requeue, empty)) = st.waiters.get_mut(&id).and_then(|waiters| {
                let queue = if interactive { &mut waiters.interactive } else { &mut waiters.normal };
                let tx = queue.pop_front()?;
                Some((tx, !queue.is_empty(), waiters.interactive.is_empty() && waiters.normal.is_empty()))
            }) else { continue };
            if requeue {
                if interactive { st.interactive.push_back(id) } else { st.normal.push_back(id) };
            }
            if empty { st.waiters.remove(&id); }
            if tx.send(()).is_err() { continue }
            st.owned = true;
            st.last_flow = Some(id);
            if interactive { st.interactive_burst = st.interactive_burst.saturating_add(1) } else { st.interactive_burst = 0 }
            return;
        }
    }
}

#[derive(Clone)]
pub struct NetworkFlow {
    scheduler: Arc<FairNetwork>,
    id: u64,
}

impl NetworkFlow {
    pub async fn turn(&self, interactive: bool) -> Result<NetworkTurn, ()> {
        let rx = {
            let mut st = self.scheduler.state.lock().unwrap();
            if !st.owned && st.interactive.is_empty() && st.normal.is_empty() {
                st.owned = true;
                st.last_flow = Some(self.id);
                st.interactive_burst = if interactive { 1 } else { 0 };
                None
            } else {
                let (tx, rx) = oneshot::channel();
                FairNetwork::enqueue(&mut st, self.id, interactive, tx);
                Some(rx)
            }
        };
        if let Some(rx) = rx { rx.await.map_err(|_| ())? }
        Ok(NetworkTurn { scheduler: self.scheduler.clone() })
    }

    pub async fn write_all<W: AsyncWrite + Unpin>(&self, w: &mut W, data: &[u8], interactive: bool) -> std::io::Result<()> {
        for chunk in data.chunks(self.scheduler.quantum) {
            let turn = self.turn(interactive).await.map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "network scheduler closed"))?;
            // The turn orders dispatch, not completion. A peer whose kernel write blocks must
            // backpressure only its own flow rather than retain the global scheduler.
            drop(turn);
            w.write_all(chunk).await?;
        }
        Ok(())
    }

    /// Charge already-read bytes through the same fair queue. This makes sustained inbound work
    /// yield between quanta and lets TCP/UDP backpressure propagate without holding a turn while an
    /// idle or slow peer is awaited.
    pub async fn charge(&self, bytes: usize, interactive: bool) -> Result<(), ()> {
        let turns = bytes.max(1).div_ceil(self.scheduler.quantum);
        for _ in 0..turns {
            drop(self.turn(interactive).await?);
        }
        Ok(())
    }
}

pub struct NetworkTurn {
    scheduler: Arc<FairNetwork>,
}

impl Drop for NetworkTurn {
    fn drop(&mut self) {
        self.scheduler.grant_next();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_capacity_is_immediate_and_waiting_flows_rotate() {
        let scheduler = FairNetwork::new(16 * 1024);
        let a = scheduler.flow(1);
        let b = scheduler.flow(2);
        let first = a.turn(false).await.unwrap();
        let a_wait = tokio::spawn({ let a = a.clone(); async move { a.turn(false).await.unwrap() } });
        let b_wait = tokio::spawn({ let b = b.clone(); async move { b.turn(false).await.unwrap() } });
        tokio::task::yield_now().await;
        drop(first);
        let b_turn = tokio::time::timeout(std::time::Duration::from_millis(50), b_wait).await.expect("another flow goes before the previous owner").unwrap();
        assert!(!a_wait.is_finished());
        drop(b_turn);
        drop(a_wait.await.unwrap());
        assert!(a.turn(false).await.is_ok(), "without contention no timer or rate cap is involved");
    }

    #[tokio::test]
    async fn control_turn_precedes_queued_bulk() {
        let scheduler = FairNetwork::new(1024);
        let owner = scheduler.flow(1).turn(false).await.unwrap();
        let bulk = scheduler.flow(2);
        let control = scheduler.flow(3);
        let bulk = tokio::spawn(async move { bulk.turn(false).await.unwrap() });
        let control = tokio::spawn(async move { control.turn(true).await.unwrap() });
        tokio::task::yield_now().await;
        drop(owner);
        let control_turn = tokio::time::timeout(std::time::Duration::from_millis(50), control).await.expect("control has a protected lane").unwrap();
        assert!(!bulk.is_finished());
        drop(control_turn);
        drop(bulk.await.unwrap());
    }
}
