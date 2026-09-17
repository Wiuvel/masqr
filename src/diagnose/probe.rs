//! `masqr probe`: the readiness check.

use masqr::transport;
use masqr::warp::Identity;

use super::packets::{dns_answers, dns_query, ipv4_udp, udp_payload};

/// The readiness check: one name resolved end to end through the tunnel.
///
/// A DNS query is the smallest exchange that proves the whole path — a single UDP datagram out and
/// one back, with no handshake state to keep. If an answer comes back carrying addresses, then the
/// identity was accepted, the endpoint agreed to CONNECT-IP, the framing is right for the carrier
/// that opened, and Cloudflare routed a packet for the address it assigned.
pub async fn run(identity: &Identity) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let (mut tunnel, stages) = transport::connect(identity).await?;
    println!(
        "tunnel    up in {} ms  ({stages})",
        started.elapsed().as_millis()
    );

    const NAME: &str = "cloudflare.com";
    const RESOLVER: [u8; 4] = [1, 1, 1, 1];
    let source: std::net::Ipv4Addr = identity.assigned_v4.parse()?;
    let query = dns_query(NAME);
    let packet = ipv4_udp(source.octets(), RESOLVER, 40000, 53, &query);

    let asked = std::time::Instant::now();
    println!(
        "query     {NAME} A → {}",
        std::net::Ipv4Addr::from(RESOLVER)
    );
    tunnel.send(packet).await?;

    // A handful of packets, not one: the tunnel carries whatever the endpoint sends, and an
    // unrelated packet arriving first should not read as a failure. With a deadline, because a
    // tunnel that is up but carries nothing would otherwise leave the check hanging with no
    // verdict at all.
    let mut seen = Vec::new();
    for _ in 0..8 {
        let waited = tokio::time::timeout(std::time::Duration::from_secs(10), tunnel.recv()).await;
        let reply = match waited {
            Ok(Ok(Some(reply))) => reply,
            Ok(Ok(None)) => {
                println!("probe     the endpoint closed the tunnel before an answer arrived");
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                println!("probe     no packet came back within 10 s");
                report_unrecognised(&seen);
                return Ok(());
            }
        };
        seen.push(describe_packet(&reply));

        let Some(payload) = udp_payload(&reply, source.octets()) else {
            continue;
        };
        let addresses = dns_answers(payload);
        if addresses.is_empty() {
            continue;
        }
        println!(
            "probe     {NAME} → {} in {} ms",
            addresses.join(", "),
            asked.elapsed().as_millis()
        );
        println!();
        println!("OK        the tunnel carries traffic end to end");
        return Ok(());
    }
    println!("probe     no answer recognised in the first packets back");
    report_unrecognised(&seen);
    Ok(())
}

/// What came back when none of it was the answer. The difference between "nothing arrived" and
/// "something arrived and was not understood" is the whole diagnosis.
fn report_unrecognised(seen: &[String]) {
    if seen.is_empty() {
        println!("          nothing came back through the tunnel at all");
        return;
    }
    println!("          {} packet(s) did come back:", seen.len());
    for line in seen {
        println!("            {line}");
    }
}

/// One line about a packet: enough to tell an ICMP error from an unrelated flow.
fn describe_packet(packet: &[u8]) -> String {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let name = match packet[9] {
                1 => "icmp",
                6 => "tcp",
                17 => "udp",
                _ => "ip",
            };
            let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            format!("{name} {src} → {dst}, {} bytes", packet.len())
        }
        Some(6) if packet.len() >= 40 => format!("ipv6, {} bytes", packet.len()),
        _ => format!("{} bytes, not an IP packet", packet.len()),
    }
}
