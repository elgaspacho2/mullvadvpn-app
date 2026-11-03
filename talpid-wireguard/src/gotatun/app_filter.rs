//! TelBlocker: drop packets from apps that the user has cut off from the network.
//!
//! Wraps an [`IpRecv`] (the TUN device, after [`super::source_filter::SourceFilter`]) and asks
//! the installed [`ConnectionPolicy`] whether each TCP or UDP connection may enter the tunnel.
//! On Android the policy is the VPN service, which looks up the app that owns the connection.
//!
//! Decisions are cached per connection for [`DECISION_TTL`], so the policy is only consulted on
//! the first packet of a connection and then every few seconds, not for every packet. When no
//! policy is installed (every platform but Android), packets pass through untouched.
//!
//! A connection whose decision can't be made (the policy returns an error) is blocked, as is a
//! TCP or UDP packet too short to read the ports from. Packets that aren't TCP or UDP (ICMP...),
//! and IP fragments after the first one, can't be tied to an app and pass through.

use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, MtuWatcher},
};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const IPV6_FRAGMENT_HEADER: u8 = 44;

/// How long a decision is reused before the policy is asked again, so rule changes apply to
/// connections that are already open.
const DECISION_TTL: Duration = Duration::from_secs(10);

/// Upper bound on cached decisions, to keep memory bounded.
const MAX_CACHED_DECISIONS: usize = 4096;

/// A TCP or UDP connection, as seen from the device: `source` is the local end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Connection {
    pub protocol: u8,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// Decides which connections may enter the tunnel.
pub trait ConnectionPolicy: Send + Sync + 'static {
    /// Whether `connection` may enter the tunnel. An error blocks it.
    fn is_allowed(&self, connection: &Connection) -> Result<bool, String>;
}

static POLICY: RwLock<Option<Arc<dyn ConnectionPolicy>>> = RwLock::new(None);

/// Install the policy used by every [`AppFilter`], replacing any previous one.
#[cfg_attr(not(target_os = "android"), expect(dead_code))]
pub fn set_policy(policy: Arc<dyn ConnectionPolicy>) {
    *POLICY
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(policy);
}

fn current_policy() -> Option<Arc<dyn ConnectionPolicy>> {
    POLICY
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Wraps an [`IpRecv`] and drops packets of connections that the [`ConnectionPolicy`] blocks.
pub struct AppFilter<R> {
    inner: R,
    decisions: HashMap<Connection, (bool, Instant)>,
}

impl<R: IpRecv> AppFilter<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            decisions: HashMap::new(),
        }
    }
}

impl<R: IpRecv> IpRecv for AppFilter<R> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let policy = current_policy();
        let decisions = &mut self.decisions;
        let packets = self.inner.recv(pool).await?;

        Ok(packets.filter_map(move |packet| {
            let Some(policy) = policy.as_deref() else {
                return Some(packet);
            };
            let bytes = packet.into_bytes();
            if is_allowed(policy, decisions, &bytes, Instant::now()) {
                bytes.try_into_ip().ok()
            } else {
                None
            }
        }))
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

/// Whether the packet in `bytes` may enter the tunnel, using and updating `decisions`.
fn is_allowed(
    policy: &dyn ConnectionPolicy,
    decisions: &mut HashMap<Connection, (bool, Instant)>,
    bytes: &[u8],
    now: Instant,
) -> bool {
    let connection = match parse_connection(bytes) {
        Ok(Some(connection)) => connection,
        Ok(None) => return true,
        Err(MalformedPacket) => return false,
    };

    if let Some(&(allowed, decided_at)) = decisions.get(&connection)
        && now.duration_since(decided_at) < DECISION_TTL
    {
        return allowed;
    }

    let allowed = policy.is_allowed(&connection).unwrap_or_else(|error| {
        log::warn!("TelBlocker: blocking {connection:?}, no decision: {error}");
        false
    });

    if decisions.len() >= MAX_CACHED_DECISIONS {
        decisions.retain(|_, (_, decided_at)| now.duration_since(*decided_at) < DECISION_TTL);
        if decisions.len() >= MAX_CACHED_DECISIONS {
            decisions.clear();
        }
    }
    decisions.insert(connection, (allowed, now));
    allowed
}

#[derive(Debug, PartialEq, Eq)]
struct MalformedPacket;

/// The TCP or UDP connection a packet belongs to, `None` when it can't be tied to one.
fn parse_connection(bytes: &[u8]) -> Result<Option<Connection>, MalformedPacket> {
    let version = bytes.first().ok_or(MalformedPacket)? >> 4;
    let (protocol, source, destination, transport) = match version {
        4 => {
            if bytes.len() < 20 {
                return Err(MalformedPacket);
            }
            let header_len = usize::from(bytes[0] & 0x0f) * 4;
            if header_len < 20 || bytes.len() < header_len {
                return Err(MalformedPacket);
            }
            // Only the first fragment carries the ports.
            let fragment_offset = u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff;
            if fragment_offset != 0 {
                return Ok(None);
            }
            let mut source = [0u8; 4];
            let mut destination = [0u8; 4];
            source.copy_from_slice(&bytes[12..16]);
            destination.copy_from_slice(&bytes[16..20]);
            (
                bytes[9],
                IpAddr::V4(Ipv4Addr::from(source)),
                IpAddr::V4(Ipv4Addr::from(destination)),
                &bytes[header_len..],
            )
        }
        6 => {
            if bytes.len() < 40 {
                return Err(MalformedPacket);
            }
            let mut next_header = bytes[6];
            let mut transport = &bytes[40..];
            // The kernel only adds a fragment header to the packets it sends; other extension
            // headers aren't used for TCP or UDP from apps.
            if next_header == IPV6_FRAGMENT_HEADER {
                if transport.len() < 8 {
                    return Err(MalformedPacket);
                }
                let fragment_offset = u16::from_be_bytes([transport[2], transport[3]]) >> 3;
                if fragment_offset != 0 {
                    return Ok(None);
                }
                next_header = transport[0];
                transport = &transport[8..];
            }
            let mut source = [0u8; 16];
            let mut destination = [0u8; 16];
            source.copy_from_slice(&bytes[8..24]);
            destination.copy_from_slice(&bytes[24..40]);
            (
                next_header,
                IpAddr::V6(Ipv6Addr::from(source)),
                IpAddr::V6(Ipv6Addr::from(destination)),
                transport,
            )
        }
        _ => return Err(MalformedPacket),
    };

    if protocol != PROTO_TCP && protocol != PROTO_UDP {
        return Ok(None);
    }
    if transport.len() < 4 {
        return Err(MalformedPacket);
    }
    let source_port = u16::from_be_bytes([transport[0], transport[1]]);
    let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
    Ok(Some(Connection {
        protocol,
        source: SocketAddr::new(source, source_port),
        destination: SocketAddr::new(destination, destination_port),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ipv4(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[142, 250, 0, 1]);
        packet.extend_from_slice(transport);
        packet
    }

    fn ipv6(next_header: u8, rest: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = next_header;
        packet[8..24].copy_from_slice(
            &"fc00:bbbb:bbbb:bb01::2"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[24..40].copy_from_slice(&"2a00:1450::1".parse::<Ipv6Addr>().unwrap().octets());
        packet.extend_from_slice(rest);
        packet
    }

    /// Ports 50000 -> 443, then padding.
    const PORTS: [u8; 8] = [0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 0];

    #[test]
    fn parses_ipv4_tcp() {
        let connection = parse_connection(&ipv4(PROTO_TCP, &PORTS)).unwrap().unwrap();
        assert_eq!(connection.protocol, PROTO_TCP);
        assert_eq!(connection.source, "10.64.0.2:50000".parse().unwrap());
        assert_eq!(connection.destination, "142.250.0.1:443".parse().unwrap());
    }

    #[test]
    fn parses_ipv6_udp_and_first_fragment() {
        let connection = parse_connection(&ipv6(PROTO_UDP, &PORTS)).unwrap().unwrap();
        assert_eq!(
            connection.destination,
            "[2a00:1450::1]:443".parse().unwrap()
        );

        let mut first_fragment = vec![PROTO_UDP, 0, 0, 0, 0, 0, 0, 1];
        first_fragment.extend_from_slice(&PORTS);
        let connection = parse_connection(&ipv6(IPV6_FRAGMENT_HEADER, &first_fragment))
            .unwrap()
            .unwrap();
        assert_eq!(connection.protocol, PROTO_UDP);
        assert_eq!(connection.source.port(), 50000);
    }

    #[test]
    fn later_fragments_and_other_protocols_are_not_connections() {
        let mut ipv4_fragment = ipv4(PROTO_UDP, &PORTS);
        ipv4_fragment[7] = 0x10; // offset != 0
        assert_eq!(parse_connection(&ipv4_fragment), Ok(None));

        let later_fragment = [PROTO_UDP, 0, 0x05, 0x00, 0, 0, 0, 1];
        assert_eq!(
            parse_connection(&ipv6(IPV6_FRAGMENT_HEADER, &later_fragment)),
            Ok(None)
        );

        const PROTO_ICMP: u8 = 1;
        assert_eq!(parse_connection(&ipv4(PROTO_ICMP, &[8, 0, 0, 0])), Ok(None));
    }

    #[test]
    fn truncated_packets_are_malformed() {
        assert_eq!(parse_connection(&[]), Err(MalformedPacket));
        assert_eq!(
            parse_connection(&ipv4(PROTO_TCP, &[0xc3])),
            Err(MalformedPacket)
        );
        assert_eq!(
            parse_connection(&ipv6(PROTO_UDP, &[])),
            Err(MalformedPacket)
        );
        assert_eq!(parse_connection(&[0x70; 40]), Err(MalformedPacket));
    }

    /// Blocks connections to port 443 and counts how often it is asked.
    struct BlockHttps {
        calls: AtomicUsize,
        fail: bool,
    }

    impl ConnectionPolicy for BlockHttps {
        fn is_allowed(&self, connection: &Connection) -> Result<bool, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err("lookup failed".to_owned());
            }
            Ok(connection.destination.port() != 443)
        }
    }

    #[test]
    fn decisions_are_cached_then_refreshed() {
        let policy = BlockHttps {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        let mut decisions = HashMap::new();
        let packet = ipv4(PROTO_TCP, &PORTS);
        let start = Instant::now();

        assert!(!is_allowed(&policy, &mut decisions, &packet, start));
        assert!(!is_allowed(
            &policy,
            &mut decisions,
            &packet,
            start + Duration::from_secs(1)
        ));
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);

        assert!(!is_allowed(
            &policy,
            &mut decisions,
            &packet,
            start + DECISION_TTL
        ));
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);

        let mut other_port = PORTS;
        other_port[3] = 0x50; // port 336
        assert!(is_allowed(
            &policy,
            &mut decisions,
            &ipv4(PROTO_TCP, &other_port),
            start
        ));
    }

    #[test]
    fn errors_and_malformed_packets_block_but_icmp_passes() {
        let policy = BlockHttps {
            calls: AtomicUsize::new(0),
            fail: true,
        };
        let mut decisions = HashMap::new();
        let now = Instant::now();

        let mut other_port = PORTS;
        other_port[3] = 0x50;
        assert!(!is_allowed(
            &policy,
            &mut decisions,
            &ipv4(PROTO_UDP, &other_port),
            now
        ));
        assert!(!is_allowed(
            &policy,
            &mut decisions,
            &ipv4(PROTO_TCP, &[0xc3]),
            now
        ));
        assert!(is_allowed(
            &policy,
            &mut decisions,
            &ipv4(1, &[8, 0, 0, 0]),
            now
        ));
    }

    #[test]
    fn cache_stays_bounded() {
        let policy = BlockHttps {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        let mut decisions = HashMap::new();
        let now = Instant::now();
        for port in 0..(MAX_CACHED_DECISIONS as u16 + 10) {
            let mut ports = PORTS;
            ports[0..2].copy_from_slice(&port.to_be_bytes());
            is_allowed(&policy, &mut decisions, &ipv4(PROTO_UDP, &ports), now);
        }
        assert!(decisions.len() <= MAX_CACHED_DECISIONS);
    }
}
