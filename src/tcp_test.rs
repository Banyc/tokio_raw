#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    use socket2::{Domain, Protocol, SockAddr, Type};

    use crate::tcp::{Ipv4PeerIps, Ipv6PeerIps, PeerIps, Tcp};

    #[tokio::test]
    async fn ipv4_tcp_syn() -> io::Result<()> {
        sudo::escalate_if_needed().unwrap();

        let socket = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;

        let client = tokio_socket2::TokioSocket2::new(socket)?;

        let src_ip_addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let dst_ip_addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let src_port = 23478;
        let dst_port = 23479;

        let ipv4_peer_ips = Ipv4PeerIps {
            src_ip: src_ip_addr,
            dst_ip: dst_ip_addr,
        };
        let dst_addr = SocketAddr::new(dst_ip_addr.into(), dst_port);

        {
            let tcp = Tcp {
                src_port,
                dst_port,
                seq_num: 0,
                ack_num: 0,
                urg: false,
                ack: false,
                psh: false,
                rst: false,
                syn: true,
                fin: false,
                window_size: 65535,
                urgent_ptr: 0,
                options: &[],
                data: &[],
            };

            let mut buf = [0u8; 20];

            let pkt_len = tcp.encode(&mut buf, &PeerIps::Ipv4(ipv4_peer_ips))?;

            let pkt = &buf[..pkt_len];

            let written_len = client
                .write(|socket| {
                    let dst_addr = SockAddr::from(dst_addr);
                    let written_len = socket.send_to(&pkt, &dst_addr)?;
                    Ok(written_len)
                })
                .await?;

            assert_eq!(written_len, pkt_len);

            eprintln!("written_len: {}", written_len);
        }

        Ok(())
    }

    #[tokio::test]
    async fn ipv4_tcp_rst() -> io::Result<()> {
        sudo::escalate_if_needed().unwrap();

        let socket = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;

        let client = tokio_socket2::TokioSocket2::new(socket)?;

        let src_ip_addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let dst_ip_addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let src_port = 23478;
        let dst_port = 23479;

        let ipv4_peer_ips = Ipv4PeerIps {
            src_ip: src_ip_addr,
            dst_ip: dst_ip_addr,
        };
        let dst_addr = SocketAddr::new(dst_ip_addr.into(), dst_port);

        {
            let mut buf = [0u8; 20];

            let tcp = Tcp {
                src_port,
                dst_port,
                seq_num: 1,
                ack_num: 0,
                urg: false,
                ack: false,
                psh: false,
                rst: true,
                syn: false,
                fin: false,
                window_size: 0,
                urgent_ptr: 0,
                options: &[],
                data: &[],
            };

            let pkt_len = tcp.encode(&mut buf, &PeerIps::Ipv4(ipv4_peer_ips))?;

            let pkt = &buf[..pkt_len];

            let written_len = client
                .write(|socket| {
                    let dst_addr = SockAddr::from(dst_addr);
                    let written_len = socket.send_to(&pkt, &dst_addr)?;
                    Ok(written_len)
                })
                .await?;

            assert_eq!(written_len, pkt_len);
        }

        Ok(())
    }

    #[tokio::test]
    async fn ipv6_tcp_syn() -> io::Result<()> {
        sudo::escalate_if_needed().unwrap();

        let socket = socket2::Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;

        let client = tokio_socket2::TokioSocket2::new(socket)?;

        let src_ip_addr: Ipv6Addr = "::1".parse().unwrap();
        let dst_ip_addr: Ipv6Addr = "::1".parse().unwrap();
        let src_port = 23478;
        let dst_port = 23479;

        let ipv6_peer_ips = Ipv6PeerIps {
            src_ip: src_ip_addr,
            dst_ip: dst_ip_addr,
        };
        let dst_addr = SocketAddr::new(dst_ip_addr.into(), dst_port);

        {
            let tcp = Tcp {
                src_port,
                dst_port,
                seq_num: 0,
                ack_num: 0,
                urg: false,
                ack: false,
                psh: false,
                rst: false,
                syn: true,
                fin: false,
                window_size: 65535,
                urgent_ptr: 0,
                options: &[],
                data: &[],
            };

            let mut buf = [0u8; 20];

            let pkt_len = tcp.encode(&mut buf, &PeerIps::Ipv6(ipv6_peer_ips))?;

            let pkt = &buf[..pkt_len];

            let written_len = client
                .write(|socket| {
                    let dst_addr = SockAddr::from(dst_addr);
                    let written_len = socket.send_to(&pkt, &dst_addr)?;
                    Ok(written_len)
                })
                .await?;

            assert_eq!(written_len, pkt_len);
        }

        Ok(())
    }
}

#[cfg(test)]
#[cfg(not(target_os = "macos"))]
mod tests_not_macos {
    use std::{
        io, mem,
        net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    };

    use socket2::{Domain, Protocol, Type};

    use crate::{
        get_eth_src_ipv4, ipv4_payload,
        tcp::{Ipv4PeerIps, PeerIps, Tcp},
    };

    #[tokio::test]
    async fn ipv4_tcp_recv() -> io::Result<()> {
        sudo::escalate_if_needed().unwrap();

        let socket = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;

        let google_ips = "www.google.com:443".to_socket_addrs()?.collect::<Vec<_>>();
        let google_ipv4 = google_ips
            .iter()
            .find(|addr| addr.is_ipv4())
            .expect("no ipv4 address found for www.google.com");

        let src_ip_addr: Ipv4Addr = get_eth_src_ipv4()?;
        let dst_ip_addr: Ipv4Addr = match google_ipv4.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!("ipv6 not supported"),
        };
        let src_port = 23478;
        let dst_port = google_ipv4.port();

        let ipv4_peer_ips = Ipv4PeerIps {
            src_ip: src_ip_addr,
            dst_ip: dst_ip_addr,
        };

        let src_addr = SocketAddr::new(src_ip_addr.into(), src_port);
        let dst_addr = SocketAddr::new(dst_ip_addr.into(), dst_port);

        socket.bind(&src_addr.into())?;
        socket.connect(&dst_addr.into())?;

        let client = tokio_socket2::TokioSocket2::new(socket)?;

        {
            let tcp = Tcp {
                src_port,
                dst_port,
                seq_num: 0,
                ack_num: 0,
                urg: false,
                ack: false,
                psh: false,
                rst: false,
                syn: true,
                fin: false,
                window_size: 65535,
                urgent_ptr: 0,
                options: &[],
                data: &[],
            };

            let mut buf = [0u8; 20];

            let pkt_len = tcp.encode(&mut buf, &PeerIps::Ipv4(ipv4_peer_ips))?;

            let pkt = &buf[..pkt_len];

            let written_len = client
                .write(|socket| {
                    let written_len = socket.send(&pkt)?;
                    Ok(written_len)
                })
                .await?;

            assert_eq!(written_len, pkt_len);

            eprintln!("written_len: {}", written_len);
        }

        {
            let mut buf = [0u8; 1024];

            loop {
                let (read_len, from, buf) = client
                    .read(|socket| {
                        let buf = unsafe {
                            mem::transmute::<&mut [u8], &mut [mem::MaybeUninit<u8>]>(&mut buf)
                        };
                        let (read_len, from) = socket.recv_from(buf)?;
                        let buf = unsafe {
                            mem::transmute::<&mut [mem::MaybeUninit<u8>], &mut [u8]>(buf)
                        };
                        Ok((read_len, from, buf))
                    })
                    .await?;

                let from = match from.as_socket() {
                    Some(from) => from,
                    None => continue,
                };

                if from.ip() != dst_ip_addr {
                    continue;
                }

                eprintln!("read_len: {}", read_len);

                let pkt = &buf[..read_len];

                let ip_payload = ipv4_payload(pkt)?;

                let tcp = Tcp::decode(ip_payload)?;

                if tcp.dst_port != src_port {
                    continue;
                }

                assert_eq!(tcp.src_port, dst_port);
                assert_eq!(tcp.dst_port, src_port);
                assert_eq!(tcp.ack_num, 1);
                assert_eq!(tcp.syn, true);
                assert_eq!(tcp.ack, true);

                break;
            }
        }

        Ok(())
    }
}
