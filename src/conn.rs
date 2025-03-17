use crate::{BUFFER_SIZE, CryptoCodec, NotEnoughBytesError, RELAY_TIMEOUT};
use bytes::{Buf, BytesMut};
use futures::StreamExt;
use futures::sink::SinkExt;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

#[derive(Debug)]
pub enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(addr) => write!(f, "{addr}"),
            Address::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl Address {
    pub fn to_socket_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        match self {
            Address::Ip(socket_addr) => Ok(vec![*socket_addr]),
            Address::Domain(host, port) => {
                let iter = (host.as_str(), *port).to_socket_addrs()?;
                Ok(iter.collect())
            }
        }
    }

    pub fn parse(mut buf: &[u8]) -> anyhow::Result<(Address, &[u8])> {
        if buf.len() < 1 {
            return Err(NotEnoughBytesError::new(1, buf.len()).into());
        }

        let atyp = buf.get_u8();

        let addr = match atyp {
            ATYP_IPV4 => {
                if buf.len() < 6 {
                    return Err(NotEnoughBytesError::new(6, buf.len()).into());
                }
                let ip = IpAddr::V4(buf.get_u32().into());
                let port = buf.get_u16();
                Address::Ip(SocketAddr::new(ip, port))
            }
            ATYP_IPV6 => {
                if buf.len() < 18 {
                    return Err(NotEnoughBytesError::new(18, buf.len()).into());
                }
                let ip = IpAddr::V6(buf.get_u128().into());
                let port = buf.get_u16();
                Address::Ip(SocketAddr::new(ip, port))
            }
            ATYP_DOMAIN => {
                if buf.len() < 1 {
                    return Err(NotEnoughBytesError::new(1, buf.len()).into());
                }

                let n = buf.get_u8() as usize;

                if buf.len() < n + 2 {
                    return Err(NotEnoughBytesError::new(n + 2, buf.len()).into());
                }

                let domain = std::str::from_utf8(&buf[..n])?.to_string();
                buf.advance(n);
                let port = buf.get_u16();
                Address::Domain(domain, port)
            }
            _ => anyhow::bail!("illegal address type: {atyp}"),
        };

        Ok((addr, buf))
    }
}

pub async fn relay(
    plain: &mut TcpStream,
    framed: &mut Framed<TcpStream, CryptoCodec<'_>>,
    addr: &Address,
) -> anyhow::Result<()>
where
{
    let mut buf = BytesMut::with_capacity(BUFFER_SIZE);
    relay_with_buf(plain, framed, &mut buf, addr).await
}

pub async fn relay_with_buf(
    plain: &mut TcpStream,
    framed: &mut Framed<TcpStream, CryptoCodec<'_>>,
    buff: &mut BytesMut,
    addr: &Address,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            count = plain.read_buf(buff) => {
                if count? == 0 {
                    break;
                }
                framed.send(buff).await?;
                buff.clear();
            }
            res = framed.next() => {
                match res.transpose()?{
                    Some(msg) => plain.write_all(&msg).await?,
                    None => break,
                }
            }
            _ = tokio::time::sleep(RELAY_TIMEOUT) => {
                tracing::warn!("relay {addr} timeout");
                break;
            }
        }
    }
    Ok(())
}
