#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
    };

    use socket2::{Domain, Protocol, SockAddr, Type};

    use crate::tcp::{Ipv4PeerIps, Tcp};

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

            let pkt_len = tcp.encode(&mut buf, Some(&ipv4_peer_ips))?;

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

            let pkt_len = tcp.encode(&mut buf, Some(&ipv4_peer_ips))?;

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
