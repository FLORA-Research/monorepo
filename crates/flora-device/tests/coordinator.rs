//! Host tests for the RS-485 poller and request builders.

use flora_device::coordinator::{
    FIRST_ADDR, LAST_ADDR, NodeState, Poller, SKIP_CYCLES, calibrate_request, discovery_request,
    poll_request, set_threshold_request, set_valve_request,
};
use flora_protocol::{
    CMD_CALIBRATE, CMD_GET_INFO, CMD_POLL, CMD_SET_THRESHOLD, CMD_SET_VALVE, decode,
};

#[test]
fn polls_rotate_round_robin() {
    let mut poller = Poller::<8>::new();
    assert!(poller.register(2, 10));
    assert!(poller.register(3, 20));
    assert!(poller.register(4, 30));

    let a = poller.next_poll().unwrap();
    let b = poller.next_poll().unwrap();
    let c = poller.next_poll().unwrap();
    assert_eq!((a.addr, a.sequence), (2, 10));
    assert_eq!((b.addr, b.sequence), (3, 20));
    assert_eq!((c.addr, c.sequence), (4, 30));
    // Wraps back to the first node with an advanced sequence.
    let d = poller.next_poll().unwrap();
    assert_eq!((d.addr, d.sequence), (2, 11));
}

#[test]
fn registration_rejects_out_of_range_and_duplicates() {
    let mut poller = Poller::<4>::new();
    assert!(!poller.register(FIRST_ADDR - 1, 1), "below range");
    assert!(!poller.register(1, 1), "aggregator address");
    assert!(!poller.register(LAST_ADDR + 1, 1), "above range");
    assert!(!poller.register(0, 1), "broadcast address");
    assert!(poller.register(FIRST_ADDR, 1));
    assert!(!poller.register(FIRST_ADDR, 2), "duplicate");
    assert_eq!(poller.len(), 1);
}

#[test]
fn deferred_node_yields_no_poll_until_the_window_passes() {
    let mut poller = Poller::<4>::new();
    poller.register(2, 1);
    for _ in 0..SKIP_CYCLES {
        poller.note_timeout(2);
    }
    assert!(matches!(poller.state(2), Some(NodeState::Deferred { .. })));
    // A lone deferred node yields nothing for SKIP_CYCLES passes.
    for cycle in 0..SKIP_CYCLES {
        assert!(
            poller.next_poll().is_none(),
            "cycle {cycle}: deferred node must not be polled"
        );
    }
    // The next pass retries it.
    assert_eq!(poller.next_poll().unwrap().addr, 2);
    assert_eq!(poller.state(2), Some(NodeState::Reachable));
}

#[test]
fn table_is_bounded() {
    let mut poller = Poller::<2>::new();
    assert!(poller.register(2, 1));
    assert!(poller.register(3, 1));
    assert!(!poller.register(4, 1), "capacity");
    assert_eq!(poller.len(), 2);
}

#[test]
fn repeated_timeouts_defer_a_node() {
    let mut poller = Poller::<4>::new();
    poller.register(2, 1);
    poller.register(3, 1);

    poller.note_timeout(2);
    assert_eq!(
        poller.state(2),
        Some(NodeState::Unreachable { failures: 1 })
    );
    // An unreachable node is skipped, but a single timeout must not
    // evict it from the table: it is retried after a reply.
    assert_eq!(poller.next_poll().unwrap().addr, 3);

    poller.note_timeout(2);
    poller.note_timeout(2);
    assert_eq!(
        poller.state(2),
        Some(NodeState::Deferred {
            remaining: SKIP_CYCLES
        })
    );
    // The deferred node is skipped without blocking the rotation.
    assert_eq!(poller.next_poll().unwrap().addr, 3);
    assert_eq!(poller.next_poll().unwrap().addr, 3);
    // After SKIP_CYCLES passes it is polled again and restored.
    let mut polls = 0;
    loop {
        let plan = poller.next_poll().expect("rotation continues");
        polls += 1;
        if plan.addr == 2 {
            break;
        }
        assert!(polls < 10, "node 2 never came back");
    }
    assert_eq!(poller.state(2), Some(NodeState::Reachable));
}

#[test]
fn a_reply_restores_reachability() {
    let mut poller = Poller::<4>::new();
    poller.register(2, 1);
    poller.note_timeout(2);
    poller.note_reply(2);
    assert_eq!(poller.state(2), Some(NodeState::Reachable));
    // Unknown addresses are ignored, not invented.
    poller.note_timeout(9);
    poller.note_reply(9);
    assert_eq!(poller.state(9), None);
}

#[test]
fn request_builders_emit_decodable_frames() {
    let (bytes, len) = discovery_request(2, 5);
    let frame = decode(&bytes[..len]).unwrap();
    assert_eq!(
        (frame.addr, frame.cmd, frame.sequence),
        (2, CMD_GET_INFO, 5)
    );
    assert!(frame.payload.is_empty());

    let (bytes, len) = poll_request(2, 5);
    let frame = decode(&bytes[..len]).unwrap();
    assert_eq!((frame.addr, frame.cmd), (2, CMD_POLL));
    assert!(frame.payload.is_empty());

    let (bytes, len) = set_valve_request(4, 7, true, 30);
    let frame = decode(&bytes[..len]).unwrap();
    assert_eq!((frame.addr, frame.cmd), (4, CMD_SET_VALVE));
    assert_eq!(frame.payload, [1, 0, 30]);

    let (bytes, len) = set_threshold_request(4, 7, 200, 188);
    let frame = decode(&bytes[..len]).unwrap();
    assert_eq!((frame.addr, frame.cmd), (4, CMD_SET_THRESHOLD));
    assert_eq!(frame.payload, [0, 200, 0, 188]);

    let (bytes, len) = calibrate_request(4, 7, true);
    let frame = decode(&bytes[..len]).unwrap();
    assert_eq!((frame.addr, frame.cmd), (4, CMD_CALIBRATE));
    assert_eq!(frame.payload, [1]);
}
