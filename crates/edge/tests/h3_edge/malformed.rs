use super::*;

/// A single zero-byte UDP datagram must be dropped without panic and leave all
/// maps empty.
#[test]
fn malformed_zero_length_datagram_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    send_udp(addr, &[]);
    listener.poll();
    assert_maps_empty(&listener);
}

/// A single-byte payload cannot be a valid QUIC header; listener must drop it.
#[test]
fn malformed_single_byte_datagram_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    send_udp(addr, &[0xFF]);
    listener.poll();
    assert_maps_empty(&listener);
}

/// Completely random garbage bytes must not panic and must leave maps clean.
#[test]
fn malformed_random_garbage_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    let garbage: Vec<u8> = (0u8..64).collect();
    send_udp(addr, &garbage);
    listener.poll();
    assert_maps_empty(&listener);
}

/// A valid-looking QUIC long header with a plausible type byte but truncated
/// body should be rejected cleanly.
#[test]
fn malformed_truncated_long_header_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    let truncated: &[u8] = &[0xC0, 0x00, 0x00, 0x00, 0x01];
    send_udp(addr, truncated);
    listener.poll();
    assert_maps_empty(&listener);
}

/// A long header with a DCID length that overflows the packet should be
/// rejected without panicking.
#[test]
fn malformed_dcid_length_overflow_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0xFF];
    pkt.extend_from_slice(&[0xAB; 8]);
    send_udp(addr, &pkt);
    listener.poll();
    assert_maps_empty(&listener);
}

/// A short-header packet destined for an unknown connection must be silently
/// dropped; it must not create a new connection entry.
#[test]
fn short_header_unknown_connection_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    let mut pkt = vec![0x40u8];
    pkt.extend_from_slice(&[
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D,
    ]);
    send_udp(addr, &pkt);
    listener.poll();
    assert_maps_empty(&listener);
}

/// A Retry packet from an unknown peer must be ignored without creating state.
#[test]
fn retry_packet_for_unknown_connection_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    let mut pkt = vec![0xF0, 0x00, 0x00, 0x00, 0x01, 0x08];
    pkt.extend_from_slice(&[0x11; 8]);
    pkt.push(0x08);
    pkt.extend_from_slice(&[0x22; 8]);
    pkt.extend_from_slice(&[0x99; 16]);
    send_udp(addr, &pkt);
    listener.poll();
    assert_maps_empty(&listener);
}

/// A Handshake packet for which no connection exists must be dropped cleanly.
#[test]
fn handshake_packet_unknown_connection_is_dropped() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();
    let mut pkt = vec![0xE0, 0x00, 0x00, 0x00, 0x01, 0x08];
    pkt.extend_from_slice(&[0x33; 8]);
    pkt.push(0x08);
    pkt.extend_from_slice(&[0x44; 8]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0xAA; 20]);
    send_udp(addr, &pkt);
    listener.poll();
    assert_maps_empty(&listener);
}

/// Repeated bursts of malformed packets must not accumulate any routing state.
#[test]
fn repeated_malformed_packets_leave_maps_consistent() {
    if !local_listener_bind_available() {
        return;
    }
    let (mut listener, addr) = make_listener();

    let payloads: &[&[u8]] = &[
        &[],
        &[0xFF],
        &[0x00; 16],
        &[0xFF; 64],
        &[0xC0, 0x00, 0x00, 0x00, 0x01, 0xFF],
        &[0x40, 0xDE, 0xAD, 0xBE, 0xEF, 0x00],
    ];

    for payload in payloads {
        send_udp(addr, payload);
        listener.poll();
    }

    assert_maps_empty(&listener);
}
