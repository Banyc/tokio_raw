#[cfg(test)]
mod tests {
    use std::{io, net::IpAddr};

    use crate::{
        echo::{recv_echo, send_ipv4_echo, send_ipv6_echo},
        icmp::IcmpEcho,
    };
    use socket2::{Domain, Protocol, Type};
    use tokio_socket2::TokioSocket2;

    #[tokio::test]
    async fn ipv4_ping() -> io::Result<()> {
        let dst_ips = vec![
            // Cloudflare DNS
            "1.1.1.1".parse().unwrap(),
            // Google DNS
            "8.8.8.8".parse().unwrap(),
        ];
        let seqs = vec![0, 1, 2, 3, 4, 5];

        let socket = if cfg!(target_os = "linux") {
            sudo::escalate_if_needed().unwrap();
            socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?
        } else {
            socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?
        };
        socket.set_nonblocking(true)?;
        let client = TokioSocket2::new(socket)?;

        let identifier = std::process::id() as u16;

        let echo_data = vec![1, 2, 3, 4, 0xff];

        for dst_ip in dst_ips {
            for &seq in &seqs {
                let echo = IcmpEcho {
                    seq,
                    identifier,
                    data: &echo_data,
                };
                let mut buf = [0u8; 64];
                let written_len = send_ipv4_echo(&mut buf, &client, dst_ip, echo).await?;
                eprintln!("written_len: {}", written_len);

                let mut buf = [0u8; 64];
                let echo =
                    recv_echo(&mut buf, &client, &IpAddr::V4(dst_ip), identifier, true).await?;

                assert_eq!(echo.seq, seq);
                assert_eq!(echo.identifier, identifier);
                assert_eq!(echo.data, &echo_data);

                eprintln!("dst: {}, echo: {:?}", dst_ip, echo);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn ipv6_ping() -> io::Result<()> {
        let dst_ips = vec![
            // Cloudflare DNS
            "2606:4700:4700::1111".parse().unwrap(),
            "2606:4700:4700::1001".parse().unwrap(),
            // Google DNS
            "2001:4860:4860::8888".parse().unwrap(),
            "2001:4860:4860::8844".parse().unwrap(),
        ];
        let seqs = vec![0, 1, 2, 3, 4, 5];

        let socket = if cfg!(target_os = "linux") {
            sudo::escalate_if_needed().unwrap();
            socket2::Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?
        } else {
            socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?
        };
        socket.set_nonblocking(true)?;
        let client = TokioSocket2::new(socket)?;

        let identifier = std::process::id() as u16;

        let echo_data = vec![1, 2, 3, 4, 0xff];

        for dst_ip in dst_ips {
            for &seq in &seqs {
                let echo = IcmpEcho {
                    seq,
                    identifier,
                    data: &echo_data,
                };
                let mut buf = [0u8; 64];
                let written_len = send_ipv6_echo(&mut buf, &client, dst_ip, echo).await?;
                eprintln!("written_len: {}", written_len);

                let mut buf = [0u8; 64];
                let echo =
                    recv_echo(&mut buf, &client, &IpAddr::V6(dst_ip), identifier, true).await?;

                assert_eq!(echo.seq, seq);
                assert_eq!(echo.identifier, identifier);
                assert_eq!(echo.data, &echo_data);

                eprintln!("dst: {}, echo: {:?}", dst_ip, echo);
            }
        }

        Ok(())
    }
}
