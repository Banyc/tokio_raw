use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{
    icmp::{IcmpEcho, IcmpKind, IcmpVersion},
    ip::ipv4_payload,
};
use socket2::SockAddr;
use tokio_socket2::TokioSocket2;

pub async fn send_ipv4_echo<'echo_buf>(
    buf: &mut [u8],
    client: &TokioSocket2,
    dst_ip: Ipv4Addr,
    echo: IcmpEcho<'echo_buf>,
) -> io::Result<usize> {
    let dst = SocketAddr::new(IpAddr::V4(dst_ip), 0);
    let ping = IcmpKind::EchoRequest(echo);
    let pkt_len = ping.encode(buf, IcmpVersion::V4)?;
    let pkt = &buf[..pkt_len];
    let dst = SockAddr::from(dst);
    let written_len = client.write(|socket| socket.send_to(&pkt, &dst)).await?;
    Ok(written_len)
}

pub async fn send_ipv6_echo<'echo_buf>(
    buf: &mut [u8],
    client: &TokioSocket2,
    dst_ip: Ipv6Addr,
    echo: IcmpEcho<'echo_buf>,
) -> io::Result<usize> {
    let dst = SocketAddr::new(IpAddr::V6(dst_ip), 0);
    let ping = IcmpKind::EchoRequest(echo);
    let pkt_len = ping.encode(buf, IcmpVersion::V6)?;
    let pkt = &buf[..pkt_len];
    let dst = SockAddr::from(dst);
    let written_len = client.write(|socket| socket.send_to(&pkt, &dst)).await?;
    Ok(written_len)
}

pub async fn recv_echo<'buf>(
    buf: &'buf mut [u8],
    client: &TokioSocket2,
    dst_ip: &IpAddr,
    identifier: u16,
    strip_ipv4_header: bool,
) -> io::Result<IcmpEcho<'buf>> {
    loop {
        let (pkt_len, from, buf) = client
            .read(|socket| {
                let buf = unsafe { mem::transmute::<&mut [u8], &mut [mem::MaybeUninit<u8>]>(buf) };
                let (pkt_len, from) = socket.recv_from(buf)?;
                let buf = unsafe { mem::transmute::<&mut [mem::MaybeUninit<u8>], &mut [u8]>(buf) };
                Ok((pkt_len, from, buf))
            })
            .await?;

        if let None = from.as_socket() {
            continue;
        }

        let from = from.as_socket().unwrap();

        if from.ip() != *dst_ip {
            continue;
        }

        let pkt = &buf[..pkt_len];

        // remove the IP header
        let ip_payload = match (from.ip(), strip_ipv4_header) {
            (IpAddr::V4(_), true) => ipv4_payload(pkt)?,
            _ => pkt,
        };

        let pong = match from.ip() {
            std::net::IpAddr::V4(_) => IcmpKind::decode(ip_payload, IcmpVersion::V4)?,
            std::net::IpAddr::V6(_) => IcmpKind::decode(ip_payload, IcmpVersion::V6)?,
        };

        if let IcmpKind::EchoReply(echo) = pong {
            if echo.identifier == identifier {
                return Ok(echo);
            }
        }
    }
}
