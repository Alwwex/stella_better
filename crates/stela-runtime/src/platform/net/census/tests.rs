use super::*;
use alloc::{format, vec, vec::Vec};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr};

const OURS: [u8; 6] = [0x0c, 0x9d, 0x92, 0x11, 0x22, 0x94];
const ROUTER: [u8; 4] = [192, 168, 1, 1];
const OFFERED: [u8; 4] = [192, 168, 1, 50];

/// An Ethernet frame holding one UDP datagram, its IPv4 and UDP checksums
/// made by smoltcp's own wire code.
fn udp_frame(
    destination: [u8; 6],
    ports: (u16, u16),
    ips: ([u8; 4], [u8; 4]),
    payload: &[u8],
) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let (source, target) = (Ipv4Address::from(ips.0), Ipv4Address::from(ips.1));
    let mut frame = vec![0u8; 14 + 20 + 8 + payload.len()];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&IPV4.to_be_bytes());
    let ip = Ipv4Repr {
        src_addr: source,
        dst_addr: target,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    };
    ip.emit(&mut Ipv4Packet::new_unchecked(&mut frame[14..]), &caps);
    let udp = UdpRepr {
        src_port: ports.0,
        dst_port: ports.1,
    };
    udp.emit(
        &mut UdpPacket::new_unchecked(&mut frame[34..]),
        &IpAddress::Ipv4(source),
        &IpAddress::Ipv4(target),
        payload.len(),
        |buffer| buffer.copy_from_slice(payload),
        &caps,
    );
    frame
}

fn bootp(client: [u8; 6], kind: u8) -> Vec<u8> {
    let mut message = vec![0u8; BOOTP];
    message[..3].copy_from_slice(&[2, 1, 6]);
    message[28..34].copy_from_slice(&client);
    message.extend_from_slice(&COOKIE);
    message.extend_from_slice(&[0, MESSAGE_TYPE, 1, kind, 255]);
    message.resize(300, 0);
    message
}

/// A DHCP server's reply of `kind` for `client`, sent to `destination`.
fn reply(destination: [u8; 6], client: [u8; 6], kind: u8) -> Vec<u8> {
    udp_frame(
        destination,
        (DHCP_SERVER, DHCP_CLIENT),
        (ROUTER, OFFERED),
        &bootp(client, kind),
    )
}

fn request(kind: u8) -> Vec<u8> {
    udp_frame(
        [0xff; 6],
        (DHCP_CLIENT, DHCP_SERVER),
        ([0; 4], [255; 4]),
        &bootp(OURS, kind),
    )
}

fn icmpv6(destination: [u8; 6], kind: u8, claimed: u16, carried: usize) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + 40 + carried];
    frame[..6].copy_from_slice(&destination);
    frame[12..14].copy_from_slice(&IPV6.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&claimed.to_be_bytes());
    frame[20] = ICMPV6;
    frame[54] = kind;
    frame
}

#[test]
fn intact_replies_are_counted_by_type_destination_and_client() {
    let mut census = Census::new(OURS);
    census.received(&reply(OURS, OURS, 2));
    census.received(&reply([0xff; 6], OURS, 5));
    census.received(&reply([0xff; 6], OURS, 6));
    census.received(&reply([0xff; 6], [2, 4, 6, 8, 10, 12], 2));
    let r = census.replies;
    assert_eq!((r.offers, r.acks, r.naks, r.foreign), (1, 1, 1, 1));
    assert_eq!(
        (r.short, r.ip_checksum, r.udp_checksum, r.other),
        (0, 0, 0, 0)
    );
    assert_eq!((census.unicast, census.broadcast, census.ipv4), (1, 3, 4));
    assert_eq!((census.short, census.fcs_left), (0, 0));
}

/// The failure this census was made to show: an adapter that takes four
/// bytes too many off each frame leaves every reply shorter than its IP
/// length, which the stack drops, while a padded ARP frame survives.
#[test]
fn a_reply_cut_four_bytes_short_is_named_as_short_not_missing() {
    let mut census = Census::new(OURS);
    let mut cut = reply(OURS, OURS, 2);
    cut.truncate(cut.len() - 4);
    census.received(&cut);
    let mut arp = vec![0u8; 56];
    arp[..6].copy_from_slice(&[0xff; 6]);
    arp[12..14].copy_from_slice(&ARP.to_be_bytes());
    census.received(&arp);
    assert_eq!(census.replies.offers, 0);
    assert_eq!(census.replies.short, 1);
    assert_eq!((census.short, census.arp), (1, 1));
    let line = format!("{census}");
    assert!(
        line.contains("dhcp offers=0 acks=0 naks=0 other=0 short=1"),
        "{line}"
    );
}

#[test]
fn corrupted_replies_are_told_apart_by_checksum() {
    let mut census = Census::new(OURS);
    let mut header = reply(OURS, OURS, 2);
    header[14 + 8] ^= 0x40; // TTL
    census.received(&header);
    let mut body = reply(OURS, OURS, 2);
    body[14 + 20 + 8 + 40] ^= 1;
    census.received(&body);
    let r = census.replies;
    assert_eq!((r.ip_checksum, r.udp_checksum, r.offers), (1, 1, 0));
    // A zero UDP checksum is none.
    let mut unchecked = reply(OURS, OURS, 2);
    unchecked[14 + 20 + 6..14 + 20 + 8].fill(0);
    census.received(&unchecked);
    assert_eq!(census.replies.offers, 1);
}

#[test]
fn an_fcs_left_on_a_frame_is_named_and_the_reply_still_counts() {
    let mut census = Census::new(OURS);
    let mut frame = reply(OURS, OURS, 2);
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    census.received(&frame);
    assert_eq!((census.fcs_left, census.replies.offers), (1, 1));
    // Padding of a minimum frame is not an FCS.
    let mut short = vec![0u8; 14 + 20 + 4];
    short[12..14].copy_from_slice(&IPV4.to_be_bytes());
    short[14] = 0x45;
    short[16..18].copy_from_slice(&20u16.to_be_bytes());
    census.received(&short);
    assert_eq!(census.fcs_left, 1);
}

#[test]
fn sent_requests_and_ipv6_router_messages_are_counted() {
    let mut census = Census::new(OURS);
    census.sent(&request(1));
    census.sent(&request(1));
    census.sent(&request(3));
    census.sent(&icmpv6([0x33, 0x33, 0, 0, 0, 2], ROUTER_SOLICITATION, 8, 8));
    census.sent(&[0u8; 6]);
    assert_eq!(
        (
            census.discovers,
            census.requests,
            census.solicitations,
            census.sent_other
        ),
        (2, 1, 1, 1)
    );
    census.received(&icmpv6(
        [0x33, 0x33, 0, 0, 0, 1],
        ROUTER_ADVERTISEMENT,
        64,
        64,
    ));
    census.received(&icmpv6(
        [0x33, 0x33, 0, 0, 0, 1],
        ROUTER_ADVERTISEMENT,
        64,
        60,
    ));
    assert_eq!(
        (census.advertisements, census.short, census.multicast),
        (1, 1, 2)
    );
}

#[test]
fn the_line_names_no_address() {
    let mut census = Census::new(OURS);
    census.received(&reply(OURS, OURS, 2));
    let line = format!("{census}");
    assert!(
        !line.contains("0c:9d") && !line.contains("192.168"),
        "{line}"
    );
    assert!(line.starts_with("in: unicast=1 "), "{line}");
}
