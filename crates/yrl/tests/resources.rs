use std::sync::Arc;
use std::time::Duration;
use yrl::resources::{OperationKind, ResourceLimits, ResourceManager};

fn manager(mut limits: ResourceLimits) -> Arc<ResourceManager> {
    // Keep these tests focused on the field they change; all memory limits must still admit one
    // maximum wire frame.
    limits.link_bytes_total = limits.link_bytes_total.max(yrl::wire::MAX_FRAME);
    limits.link_bytes_per_key = limits.link_bytes_per_key.max(yrl::wire::MAX_FRAME);
    limits.link_bytes_per_account = limits.link_bytes_per_account.max(yrl::wire::MAX_FRAME);
    Arc::new(ResourceManager::new(limits).unwrap())
}

#[test]
fn resource_limits_reject_a_link_pool_that_cannot_hold_one_legal_frame() {
    let mut limits = ResourceLimits::default();
    limits.link_bytes_total = yrl::wire::MAX_FRAME - 1;
    assert!(ResourceManager::new(limits).is_err());
}

#[test]
fn session_admission_is_hierarchical_and_drop_releases_every_quota() {
    let resources = manager(ResourceLimits::default());
    let first = resources.try_session(b"key-a", "anna", 10, 10, 1).unwrap();
    assert!(
        resources.try_session(b"key-b", "anna", 10, 10, 1).is_none(),
        "one account cannot monopolize session admission through many keys"
    );
    assert!(
        resources.try_session(b"key-a", "bob", 10, 1, 10).is_none(),
        "one device key cannot monopolize admission through many accounts"
    );
    drop(first);
    assert!(
        resources.try_session(b"key-b", "anna", 10, 10, 1).is_some(),
        "all principal counters are released with the session permit"
    );
}

#[test]
fn operation_admission_is_global_per_session_per_key_per_account_and_per_kind() {
    let mut limits = ResourceLimits::default();
    limits.max_operations_total = 4;
    limits.max_operations_per_session = 1;
    limits.max_operations_per_key = 2;
    limits.max_operations_per_account = 2;
    limits.max_exec_total = 3;
    let resources = manager(limits);

    let a1 = resources
        .try_operation(1, b"key-a", "anna", OperationKind::Exec)
        .unwrap();
    assert!(
        resources
            .try_operation(1, b"key-a", "anna", OperationKind::Pty)
            .is_none(),
        "a single session has its own share"
    );
    let _a2 = resources
        .try_operation(2, b"key-a", "anna", OperationKind::Exec)
        .unwrap();
    assert!(
        resources
            .try_operation(3, b"key-a", "bob", OperationKind::Exec)
            .is_none(),
        "the device-key quota spans accounts"
    );
    assert!(
        resources
            .try_operation(3, b"key-b", "anna", OperationKind::Exec)
            .is_none(),
        "the account quota spans device keys"
    );
    let _other = resources
        .try_operation(3, b"key-b", "bob", OperationKind::Exec)
        .unwrap();
    assert_eq!(resources.usage().operations, 3);

    drop(a1);
    assert!(
        resources
            .try_operation(1, b"key-a", "anna", OperationKind::Pty)
            .is_some(),
        "completion releases all operation counters"
    );
}

#[test]
fn authenticated_network_admission_is_hierarchical_and_raii() {
    let mut limits = ResourceLimits::default();
    limits.max_network_connections_total = 3;
    limits.max_network_connections_per_key = 2;
    limits.max_network_connections_per_account = 2;
    let resources = manager(limits);
    let a1 = resources.try_network_connection(b"key-a", "anna").unwrap();
    let _a2 = resources.try_network_connection(b"key-a", "anna").unwrap();
    assert!(resources.try_network_connection(b"key-a", "bob").is_none(), "one authenticated device cannot monopolize through accounts");
    assert!(resources.try_network_connection(b"key-b", "anna").is_none(), "one account cannot monopolize through devices");
    let _other = resources.try_network_connection(b"key-b", "bob").unwrap();
    assert_eq!(resources.usage().network_connections, 3);
    drop(a1);
    assert!(resources.try_network_connection(b"key-c", "carol").is_some(), "disconnect releases every network quota level");
}

#[tokio::test]
async fn bulk_memory_cannot_consume_the_interactive_reserve() {
    let capacity = 4 * yrl::wire::MAX_FRAME;
    let mut limits = ResourceLimits::default();
    limits.link_bytes_total = capacity;
    limits.link_bytes_per_key = capacity;
    limits.link_bytes_per_account = capacity;
    let resources = manager(limits);
    let session = resources.try_session(b"key", "anna", 1, 1, 1).unwrap();
    let budget = session.link_budget();
    let reserve = (capacity / 8)
        .min(256 << 10)
        .min(capacity - yrl::wire::MAX_FRAME);
    let bulk = budget.reserve(capacity - reserve, false).await.unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(10), budget.reserve(1, false))
            .await
            .is_err(),
        "bulk waits at the protected boundary"
    );
    let interactive =
        tokio::time::timeout(Duration::from_millis(10), budget.reserve(reserve, true))
            .await
            .expect("interactive traffic uses the protected reserve")
            .unwrap();
    assert_eq!(resources.usage().link_bytes, capacity);

    drop(interactive);
    drop(bulk);
    assert_eq!(resources.usage().link_bytes, 0);
}
