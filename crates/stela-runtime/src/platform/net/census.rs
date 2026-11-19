//! What an adapter's frames were, for the log line of an attempt that got
//! no address: counts by destination and protocol, the DHCPv4 replies and
//! router advertisements among them, and whether each frame's IP header and
//! checksums fit the bytes the adapter gave. A reply the router sent but the
//! adapter cut short (a frame shorter than its IP length) or corrupted is
//! told apart from one that never came. It keeps counts only, never an
//! address.

use core::fmt;

const ETHERNET: usize = 14;
const ARP: u16 = 0x0806;
const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86dd;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
const DHCP_SERVER: u16 = 67;
const DHCP_CLIENT: u16 = 68;
const ROUTER_SOLICITATION: u8 = 133;
const ROUTER_ADVERTISEMENT: u8 = 134;
/// BOOTP's fixed part, then the DHCP magic cookie.
const BOOTP: usize = 236;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
const MESSAGE_TYPE: u8 = 53;

/// The DHCPv4 replies an adapter received, by message type and by what was
/// wrong with those that cannot be used.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Replies {
    pub offers: u64,
    pub acks: u64,
    pub naks: u64,
    pub other: u64,
    /// The frame holds fewer bytes than its IPv4 or UDP length says.
    pub short: u64,
    pub ip_checksum: u64,
    pub udp_checksum: u64,
    /// For another client's hardware address.
    pub foreign: u64,
}

/// The frames one adapter sent and received.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Census {
    mac: [u8; 6],
    pub unicast: u64,
    pub broadcast: u64,
    pub multicast: u64,
    pub arp: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub other: u64,
    /// IPv4 or IPv6 frames shorter than their IP length: bytes lost on the
    /// way in, which the stack drops as truncated.
    pub short: u64,
    /// IPv4 frames longer than the minimum with exactly four bytes past
    /// their IP length: an FCS left on the frame.
    pub fcs_left: u64,
    pub replies: Replies,
    pub advertisements: u64,
    pub discovers: u64,
    pub requests: u64,
    pub solicitations: u64,
    pub sent_other: u64,
}

impl Census {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            ..Self::default()
        }
    }

    /// Count one frame the adapter received.
    pub fn received(&mut self, frame: &[u8]) {
        let Some((destination, kind, payload)) = ethernet(frame) else {
            self.other += 1;
            return;
        };
        if destination == [0xff; 6] {
            self.broadcast += 1;
        } else if destination[0] & 1 != 0 {
            self.multicast += 1;
        } else {
            self.unicast += 1;
        }
        match kind {
            ARP => self.arp += 1,
            IPV4 => {
                self.ipv4 += 1;
                self.received_ipv4(payload, frame.len());
            }
            IPV6 => {
                self.ipv6 += 1;
                match ipv6(payload) {
                    Ipv6::Short => self.short += 1,
                    Ipv6::Icmp(ROUTER_ADVERTISEMENT) => self.advertisements += 1,
                    _ => {}
                }
            }
            _ => self.other += 1,
        }
    }

    fn received_ipv4(&mut self, packet: &[u8], frame: usize) {
        let Some(header) = Ipv4Header::parse(packet) else {
            self.short += 1;
            return;
        };
        if packet.len() < header.total {
            self.short += 1;
        } else if frame > 60 && packet.len() == header.total + 4 {
            self.fcs_left += 1;
        }
        let Some((source, destination, datagram)) = header.udp(packet) else {
            return;
        };
        if (source, destination) != (DHCP_SERVER, DHCP_CLIENT) {
            return;
        }
        let replies = &mut self.replies;
        if packet.len() < header.total || datagram.short {
            replies.short += 1;
            return;
        }
        if !header.checksum_ok(packet) {
            replies.ip_checksum += 1;
            return;
        }
        if !header.udp_checksum_ok(packet) {
            replies.udp_checksum += 1;
            return;
        }
        let message = &packet[header.length + 8..header.total];
        if message.get(28..34) != Some(&self.mac[..]) {
            replies.foreign += 1;
            return;
        }
        match message_type(message) {
            Some(2) => replies.offers += 1,
            Some(5) => replies.acks += 1,
            Some(6) => replies.naks += 1,
            _ => replies.other += 1,
        }
    }

    /// Count one frame the adapter sent.
    pub fn sent(&mut self, frame: &[u8]) {
        let Some((_, kind, payload)) = ethernet(frame) else {
            self.sent_other += 1;
            return;
        };
        let counted = match kind {
            IPV4 => Ipv4Header::parse(payload)
                .and_then(|header| {
                    let (source, destination, _) = header.udp(payload)?;
                    ((source, destination) == (DHCP_CLIENT, DHCP_SERVER))
                        .then(|| message_type(payload.get(header.length + 8..)?))
                        .flatten()
                })
                .map(|message| match message {
                    1 => self.discovers += 1,
                    3 => self.requests += 1,
                    _ => self.sent_other += 1,
                }),
            IPV6 => matches!(ipv6(payload), Ipv6::Icmp(ROUTER_SOLICITATION))
                .then(|| self.solicitations += 1),
            _ => None,
        };
        if counted.is_none() {
            self.sent_other += 1;
        }
    }
}

impl fmt::Display for Census {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = &self.replies;
        write!(
            f,
            "in: unicast={} broadcast={} multicast={} arp={} ipv4={} ipv6={} other={} \
             short={} fcs_left={} dhcp offers={} acks={} naks={} other={} short={} \
             ip_checksum={} udp_checksum={} foreign={} router_advertisements={}; \
             out: dhcp discovers={} requests={} router_solicitations={} other={}",
            self.unicast,
            self.broadcast,
            self.multicast,
            self.arp,
            self.ipv4,
            self.ipv6,
            self.other,
            self.short,
            self.fcs_left,
            r.offers,
            r.acks,
            r.naks,
            r.other,
            r.short,
            r.ip_checksum,
            r.udp_checksum,
            r.foreign,
            self.advertisements,
            self.discovers,
            self.requests,
            self.solicitations,
            self.sent_other,
        )
    }
}

fn ethernet(frame: &[u8]) -> Option<([u8; 6], u16, &[u8])> {
    let destination = frame.get(..6)?.try_into().ok()?;
    let kind = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    Some((destination, kind, frame.get(ETHERNET..)?))
}

struct Ipv4Header {
    length: usize,
    total: usize,
    protocol: u8,
    fragment: bool,
}

/// A UDP datagram's ports and whether its length runs past the packet.
struct Datagram {
    short: bool,
}

impl Ipv4Header {
    fn parse(packet: &[u8]) -> Option<Self> {
        let first = *packet.first()?;
        let length = usize::from(first & 0xf) * 4;
        if first >> 4 != 4 || length < 20 || packet.len() < length {
            return None;
        }
        let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total < length {
            return None;
        }
        let flags = u16::from_be_bytes([packet[6], packet[7]]);
        Some(Self {
            length,
            total,
            protocol: packet[9],
            fragment: flags & 0x3fff != 0,
        })
    }

    fn udp(&self, packet: &[u8]) -> Option<(u16, u16, Datagram)> {
        if self.protocol != UDP || self.fragment {
            return None;
        }
        let header = packet.get(self.length..self.length + 8)?;
        let source = u16::from_be_bytes([header[0], header[1]]);
        let destination = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let short = length < 8 || self.length + length > self.total.min(packet.len());
        Some((source, destination, Datagram { short }))
    }

    fn checksum_ok(&self, packet: &[u8]) -> bool {
        fold(sum(&packet[..self.length], 0)) == 0xffff
    }

    /// A zero UDP checksum is none (RFC 768).
    fn udp_checksum_ok(&self, packet: &[u8]) -> bool {
        let udp = &packet[self.length..self.total];
        if u16::from_be_bytes([udp[6], udp[7]]) == 0 {
            return true;
        }
        let mut pseudo = [0u8; 12];
        pseudo[..8].copy_from_slice(&packet[12..20]);
        pseudo[9] = UDP;
        pseudo[10..].copy_from_slice(&(udp.len() as u16).to_be_bytes());
        fold(sum(udp, sum(&pseudo, 0))) == 0xffff
    }
}

enum Ipv6 {
    Short,
    Icmp(u8),
    Other,
}

fn ipv6(packet: &[u8]) -> Ipv6 {
    let Some(header) = packet.get(..40) else {
        return Ipv6::Short;
    };
    let payload = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if packet.len() < 40 + payload {
        return Ipv6::Short;
    }
    match (header[6], packet.get(40)) {
        (ICMPV6, Some(&kind)) => Ipv6::Icmp(kind),
        _ => Ipv6::Other,
    }
}

/// The DHCP message type (option 53) of a BOOTP message, if it has one.
fn message_type(message: &[u8]) -> Option<u8> {
    if message.get(BOOTP..BOOTP + 4)? != COOKIE {
        return None;
    }
    let mut options = message.get(BOOTP + 4..)?;
    loop {
        match *options.first()? {
            0 => options = &options[1..],
            255 => return None,
            code => {
                let length = usize::from(*options.get(1)?);
                let value = options.get(2..2 + length)?;
                if code == MESSAGE_TYPE {
                    return value.first().copied();
                }
                options = &options[2 + length..];
            }
        }
    }
}

fn sum(bytes: &[u8], mut total: u32) -> u32 {
    let (words, remainder) = bytes.as_chunks::<2>();
    for word in words {
        total += u32::from(u16::from_be_bytes(*word));
    }
    if let [last] = remainder {
        total += u32::from(*last) << 8;
    }
    total
}

fn fold(mut total: u32) -> u16 {
    while total > 0xffff {
        total = (total & 0xffff) + (total >> 16);
    }
    total as u16
}

#[cfg(test)]
mod tests;
