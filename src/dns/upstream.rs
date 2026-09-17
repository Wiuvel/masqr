//! Asking an upstream resolver, and checking the reply belongs to the query.
//!
//! A query is forwarded byte for byte and the reply returned byte for byte. Nothing here builds or
//! rewrites a message; only enough of the reply header is read to match it to its query.
//!
//! Two transports, distinguished by what a filtered line can do to them rather than by how they are
//! dialled. Plain DNS is readable and forgeable in flight, so the application keeps a resolver on it
//! only for names it is content to expose. DoH is neither.
//!
//! Which side of the tunnel a query leaves by is the caller's to say. A resolver reached through the
//! tunnel is reached that way because its address is routed there, and is asked with an unbound
//! socket. A resolver asked directly is asked from the address the caller hands over — the line's
//! address for that destination — which keeps it off the tunnel even when its address is routed in
//! for everything else on the machine.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};

use super::policy::{Kind, Resolver};

/// How long one attempt at an upstream may take.
///
/// Bounded well under what a client waits before retrying: a resolver that has not answered in four
/// seconds will not be the one that answers, and holding the query open past that only means the
/// machine asks again while this one is still waiting.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// The port every declared resolver is asked on. Not configurable, because a resolver on another
/// port is a thing no application here has ever needed and every extra knob is a thing to get wrong.
const DNS_PORT: u16 = 53;

/// The most a reply may be. A UDP datagram cannot exceed this in practice, and it bounds what a TCP
/// reply may claim its length is.
const MAX_MESSAGE: usize = 65_535;

/// Bytes of header every message has.
const HEADER_LEN: usize = 12;

/// The truncation bit, in the second byte of the flags.
const FLAG_TRUNCATED: u8 = 0x02;

#[derive(Debug, thiserror::Error)]
/// Why an upstream could not answer, or could not be built to be asked.
pub enum UpstreamError {
    #[error("`{0}` is not a url")]
    BadUrl(String),
    #[error("the url `{0}` names no host, so there is nothing to check a certificate against")]
    NoHost(String),
    #[error("preparing the client for `{id}`: {source}")]
    Client { id: String, source: reqwest::Error },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("the resolver did not answer within {} s", QUERY_TIMEOUT.as_secs())]
    Timeout,
    #[error("the resolver answered with http {0}")]
    Http(reqwest::StatusCode),
    #[error("asking the resolver: {0}")]
    Request(reqwest::Error),
    #[error("the answer is {0} bytes, which is too short to be a dns message")]
    TooShort(usize),
    #[error("the answer carries another question's id")]
    Mismatched,
}

/// One upstream, prepared once and asked many times.
#[derive(Debug)]
pub enum Upstream {
    Plain { address: IpAddr },
    Doh(Doh),
}

/// A DoH resolver: where it is dialled, the name its certificate is checked against, and the client.
#[derive(Debug)]
pub struct Doh {
    id: String,
    url: String,
    /// The name the certificate is checked against, pinned to the declared address.
    host: String,
    dialled: SocketAddr,
    /// The client, and the local address it dials from.
    ///
    /// Kept rather than built per query because a DoH client carries a connection pool and a TLS
    /// session, and building one per query would put a full handshake in front of every name the
    /// machine looks up. Replaced when the address it has to dial from changes — the line moved —
    /// since a pooled connection from the old address is a connection from nowhere.
    bound: Mutex<Bound>,
}

/// A DoH client and the address its connections are made from.
#[derive(Debug)]
pub struct Bound {
    from: Option<IpAddr>,
    client: reqwest::Client,
}

impl Upstream {
    /// Ask, and return the reply as it came back. `from` is the local address to ask from, or `None`
    /// for wherever the routing table sends the query.
    pub async fn ask(&self, query: &[u8], from: Option<IpAddr>) -> Result<Vec<u8>, UpstreamError> {
        let wanted = transaction_id(query)?;
        let reply = match self {
            Upstream::Plain { address } => {
                Self::ask_plain(SocketAddr::new(*address, DNS_PORT), from, query).await?
            }
            Upstream::Doh(doh) => {
                let client = doh.client_from(from)?;
                Self::ask_doh(&client, &doh.url, query).await?
            }
        };

        if transaction_id(&reply)? != wanted {
            return Err(UpstreamError::Mismatched);
        }
        Ok(reply)
    }

    /// UDP first, and TCP when the answer says it did not fit.
    ///
    /// The fallback is not optional politeness: a truncated answer carries a header and no
    /// addresses, so a forwarder that passed it on would be handing the machine an empty answer for
    /// a name that has plenty of them.
    async fn ask_plain(
        target: SocketAddr,
        from: Option<IpAddr>,
        query: &[u8],
    ) -> Result<Vec<u8>, UpstreamError> {
        let socket = UdpSocket::bind(SocketAddr::new(local(target, from), 0)).await?;
        // Connected, so the kernel drops anything that did not come from the resolver. It is the
        // cheapest half of not accepting an answer from whoever shouted loudest.
        socket.connect(target).await?;
        socket.send(query).await?;

        let mut buffer = vec![0u8; 1500];
        let read = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        buffer.truncate(read);

        if is_truncated(&buffer)? {
            return Self::ask_over_tcp(target, from, query).await;
        }
        Ok(buffer)
    }

    /// The same query over TCP, where a message is preceded by its length.
    async fn ask_over_tcp(
        target: SocketAddr,
        from: Option<IpAddr>,
        query: &[u8],
    ) -> Result<Vec<u8>, UpstreamError> {
        let exchange = async {
            let socket = match target {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            if let Some(from) = from {
                socket.bind(SocketAddr::new(from, 0))?;
            }
            let mut stream = socket.connect(target).await?;
            stream.set_nodelay(true)?;

            let length = u16::try_from(query.len()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "the query is too long")
            })?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(query).await?;
            stream.flush().await?;

            let mut header = [0u8; 2];
            stream.read_exact(&mut header).await?;
            let length = usize::from(u16::from_be_bytes(header)).min(MAX_MESSAGE);
            let mut reply = vec![0u8; length];
            stream.read_exact(&mut reply).await?;
            Ok::<_, std::io::Error>(reply)
        };

        tokio::time::timeout(QUERY_TIMEOUT, exchange)
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(UpstreamError::Io)
    }

    async fn ask_doh(
        client: &reqwest::Client,
        url: &str,
        query: &[u8],
    ) -> Result<Vec<u8>, UpstreamError> {
        let response = client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    UpstreamError::Timeout
                } else {
                    UpstreamError::Request(e)
                }
            })?;

        if !response.status().is_success() {
            return Err(UpstreamError::Http(response.status()));
        }
        let body = response.bytes().await.map_err(UpstreamError::Request)?;
        Ok(body.to_vec())
    }
}

impl Doh {
    /// The DoH client that dials from `from`, built afresh when that is not the address the current
    /// one dials from.
    fn client_from(&self, from: Option<IpAddr>) -> Result<reqwest::Client, UpstreamError> {
        // Nothing under this lock can panic; the recovery is here because it is taken by every
        // query, and one poisoned by a bug elsewhere must not become a resolver that answers nothing.
        let mut bound = self
            .bound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if bound.from != from {
            bound.client = doh_client(&self.host, self.dialled, from).map_err(|source| {
                UpstreamError::Client {
                    id: self.id.clone(),
                    source,
                }
            })?;
            bound.from = from;
        }
        // A handle on the same pool, not a second client.
        Ok(bound.client.clone())
    }
}

/// The local address a socket to `target` is bound to: `from` when given, and otherwise the unbound
/// address of the target's family.
fn local(target: SocketAddr, from: Option<IpAddr>) -> IpAddr {
    from.unwrap_or(match target {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    })
}

/// A DoH client for one resolver. The host is pinned to the declared address, so asking this
/// resolver never needs a name resolved first — which it could not be, since this *is* the thing
/// that resolves names.
fn doh_client(
    host: &str,
    dialled: SocketAddr,
    from: Option<IpAddr>,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .resolve(host, dialled)
        .local_address(from)
        .https_only(true)
        .timeout(QUERY_TIMEOUT)
        .build()
}

/// Every declared resolver, ready to be asked.
#[derive(Debug, Default)]
pub struct Upstreams {
    by_id: HashMap<String, Upstream>,
}

impl Upstreams {
    /// Prepare a client for each resolver. Fails as a whole: a policy half of whose resolvers work
    /// would answer some names and quietly fail others, which is worse than not being installed.
    pub fn build<'a>(resolvers: impl Iterator<Item = &'a Resolver>) -> Result<Self, UpstreamError> {
        let mut by_id = HashMap::new();
        for resolver in resolvers {
            let upstream = match resolver.kind {
                Kind::Plain => Upstream::Plain {
                    address: resolver.address,
                },
                Kind::Doh => {
                    let url = resolver.url.as_deref().unwrap_or_default();
                    let parsed = reqwest::Url::parse(url)
                        .map_err(|_| UpstreamError::BadUrl(url.to_owned()))?;
                    let host = parsed
                        .host_str()
                        .ok_or_else(|| UpstreamError::NoHost(url.to_owned()))?
                        .to_owned();
                    let dialled = SocketAddr::new(resolver.address, parsed.port().unwrap_or(443));
                    // Built now, unbound, so a resolver that cannot have a client is refused with the
                    // policy rather than on the first name it is asked about.
                    let client = doh_client(&host, dialled, None).map_err(|source| {
                        UpstreamError::Client {
                            id: resolver.id.clone(),
                            source,
                        }
                    })?;
                    Upstream::Doh(Doh {
                        id: resolver.id.clone(),
                        url: url.to_owned(),
                        host,
                        dialled,
                        bound: Mutex::new(Bound { from: None, client }),
                    })
                }
            };
            by_id.insert(resolver.id.clone(), upstream);
        }
        Ok(Self { by_id })
    }

    /// The client for a resolver named by a rule, or nothing when the policy named none.
    pub fn get(&self, id: &str) -> Option<&Upstream> {
        self.by_id.get(id)
    }
}

fn transaction_id(message: &[u8]) -> Result<u16, UpstreamError> {
    if message.len() < HEADER_LEN {
        return Err(UpstreamError::TooShort(message.len()));
    }
    Ok(u16::from_be_bytes([message[0], message[1]]))
}

fn is_truncated(message: &[u8]) -> Result<bool, UpstreamError> {
    if message.len() < HEADER_LEN {
        return Err(UpstreamError::TooShort(message.len()));
    }
    Ok(message[3] & FLAG_TRUNCATED != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::policy::Via;

    fn message(id: u16, truncated: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..2].copy_from_slice(&id.to_be_bytes());
        bytes[2] = 0x81;
        bytes[3] = if truncated { FLAG_TRUNCATED } else { 0 };
        bytes
    }

    fn plain(address: &str) -> Resolver {
        Resolver {
            id: "test".into(),
            kind: Kind::Plain,
            address: address.parse().unwrap(),
            url: None,
            via: Via::Direct,
        }
    }

    /// A resolver that answers on a port of its own, so the exchange can be driven end to end
    /// without a network. It answers UDP once and, if asked, the same over TCP.
    async fn stub(reply: Vec<u8>, over_tcp: Option<Vec<u8>>) -> SocketAddr {
        // One port for both, as a resolver has. The system picks the UDP one, and the same number
        // can already be held over TCP by another test running beside this one — so a pair that
        // does not bind is let go and another is taken.
        let (udp, tcp, port) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(tcp) = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await {
                break (udp, tcp, port);
            }
        };

        tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            let (_, from) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&reply, from).await.unwrap();
        });
        if let Some(reply) = over_tcp {
            tokio::spawn(async move {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut query).await.unwrap();
                stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&reply).await.unwrap();
                stream.flush().await.unwrap();
            });
        }
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    fn loopback() -> Option<IpAddr> {
        Some("127.0.0.1".parse().unwrap())
    }

    #[tokio::test]
    async fn a_plain_resolver_answers_over_udp() {
        let target = stub(message(0x1234, false), None).await;
        let reply = Upstream::ask_plain(target, None, &message(0x1234, false))
            .await
            .unwrap();
        assert_eq!(transaction_id(&reply).unwrap(), 0x1234);
    }

    /// A truncated answer carries no addresses. Passing it on would report "this name has none",
    /// which is a different and wrong answer.
    #[tokio::test]
    async fn a_truncated_answer_is_asked_again_over_tcp() {
        let mut full = message(0x1234, false);
        full.extend_from_slice(&[0xaa; 40]);
        let target = stub(message(0x1234, true), Some(full)).await;

        let reply = Upstream::ask_plain(target, None, &message(0x1234, false))
            .await
            .unwrap();
        assert_eq!(
            reply.len(),
            HEADER_LEN + 40,
            "the whole answer, not the stub"
        );
    }

    /// Asked from a given address, over both transports: the socket is bound to it before it
    /// connects, and an exchange from a bound address still completes. Loopback is the one address
    /// every machine has that also reaches the stub.
    #[tokio::test]
    async fn a_query_asked_from_an_address_is_asked_from_it_over_udp_and_tcp() {
        let mut full = message(0x4321, false);
        full.extend_from_slice(&[0xbb; 8]);
        let target = stub(message(0x4321, true), Some(full)).await;

        let reply = Upstream::ask_plain(target, loopback(), &message(0x4321, false))
            .await
            .unwrap();
        assert_eq!(reply.len(), HEADER_LEN + 8);
    }

    /// The address a socket is bound to when none is given is the target family's unbound one.
    #[test]
    fn without_an_address_the_socket_is_left_to_the_routing_table() {
        let v4: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let v6: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        assert_eq!(local(v4, None), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(local(v6, None), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(local(v4, loopback()), loopback().unwrap());
    }

    /// A DoH client dials from one address for its whole life, so a new address means a new client
    /// — and the same address again must not throw away the pool and its TLS session.
    #[test]
    fn a_doh_client_is_rebuilt_only_when_the_address_it_dials_from_changes() {
        let resolver = Resolver {
            id: "doh".into(),
            kind: Kind::Doh,
            address: "8.8.8.8".parse().unwrap(),
            url: Some("https://dns.google/dns-query".into()),
            via: Via::Direct,
        };
        let prepared = Upstreams::build([&resolver].into_iter()).unwrap();
        let upstream = prepared.get("doh").unwrap();
        let Upstream::Doh(doh) = upstream else {
            panic!("a DoH resolver prepares a DoH upstream");
        };
        let from = |bound: &Mutex<Bound>| bound.lock().unwrap().from;

        assert_eq!(from(&doh.bound), None, "prepared unbound");
        doh.client_from(loopback()).unwrap();
        assert_eq!(from(&doh.bound), loopback());
        doh.client_from(loopback()).unwrap();
        assert_eq!(
            from(&doh.bound),
            loopback(),
            "the same address keeps the client"
        );
        doh.client_from(None).unwrap();
        assert_eq!(from(&doh.bound), None);
    }

    /// The id is the only thing tying an answer to a question. Accepting one that does not match is
    /// how a forwarder hands the machine somebody else's answer.
    #[test]
    fn an_answer_carrying_another_id_is_refused() {
        let query = message(0x1111, false);
        let reply = message(0x2222, false);
        assert_eq!(transaction_id(&query).unwrap(), 0x1111);
        assert!(matches!(
            transaction_id(&reply).map(|id| id == 0x1111),
            Ok(false)
        ));
    }

    #[test]
    fn something_too_short_to_be_a_message_is_refused_rather_than_indexed_into() {
        for length in 0..HEADER_LEN {
            assert!(matches!(
                transaction_id(&vec![0u8; length]),
                Err(UpstreamError::TooShort(_))
            ));
            assert!(matches!(
                is_truncated(&vec![0u8; length]),
                Err(UpstreamError::TooShort(_))
            ));
        }
    }

    #[test]
    fn a_doh_resolver_with_an_unusable_url_is_refused_when_it_is_prepared() {
        let bad = Resolver {
            id: "doh".into(),
            kind: Kind::Doh,
            address: "1.1.1.1".parse().unwrap(),
            url: Some("not a url".into()),
            via: Via::Direct,
        };
        assert!(matches!(
            Upstreams::build([&bad].into_iter()),
            Err(UpstreamError::BadUrl(_))
        ));
    }

    #[test]
    fn every_declared_resolver_is_prepared_under_its_own_name() {
        let one = plain("1.1.1.1");
        let mut two = plain("8.8.8.8");
        two.id = "other".into();
        let prepared = Upstreams::build([&one, &two].into_iter()).unwrap();
        assert!(prepared.get("test").is_some());
        assert!(prepared.get("other").is_some());
        assert!(prepared.get("absent").is_none());
    }
}
