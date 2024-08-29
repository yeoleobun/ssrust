use crate::NotEnoughBytesError;
use bytes::Buf;
use std::fmt;
use std::net::IpAddr;

pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(ip) => write!(f, "{}", ip),
            Address::Domain(host) => write!(f, "{}", host),
        }
    }
}

pub fn parse_address(mut buf: &[u8]) -> anyhow::Result<(Address, u16, &[u8])> {
    anyhow::ensure!(buf.len() >= 7, NotEnoughBytesError::new(7, buf.len()));
    let addr = match buf.get_u8() {
        1 => Address::Ip(IpAddr::V4(buf.get_u32().into())),
        4 => {
            anyhow::ensure!(buf.len() >= 18, NotEnoughBytesError::new(18, buf.len()));
            Address::Ip(IpAddr::V6(buf.get_u128().into()))
        }
        3 => {
            let n = buf.get_u8() as usize;
            anyhow::ensure!(
                buf.len() >= n + 2,
                NotEnoughBytesError::new(n + 2, buf.len())
            );
            Address::Domain(String::from_utf8(buf.copy_to_bytes(n).to_vec())?)
        }
        _ => anyhow::bail!("illegal address"),
    };
    Ok((addr, buf.get_u16(), buf))
}

#[macro_export]
macro_rules! listen {
    ($listener: expr) => {{
        tracing::info!("listening on: {}", $listener.local_addr().unwrap());
        loop {
            tokio::select! {
                res = tokio::net::TcpListener::accept(&$listener) => {
                    match res{
                        Ok((stream,_)) => {
                            tokio::spawn(futures::future::FutureExt::map(process(stream), |res| {
                                res.inspect_err(|err| tracing::warn!("{:#}",err))
                            }));
                        },
                        Err(cause) => tracing::warn!("accept err: {cause}")
                    }
                },
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("shutdown");
                    break;
                }
            }
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! relay {
    ($plain: expr, $framed: expr, $addr: expr) => {{
        let mut buff = bytes::BytesMut::with_capacity($crate::BUFFER_SIZE);
        $crate::relay!($plain, $framed, $addr, buff)
    }};
    ($plain: expr, $framed: expr, $addr: expr, $buff: expr) => {{
        loop {
            tokio::select! {
                count = tokio::io::AsyncReadExt::read_buf(&mut $plain, &mut $buff) => {
                    if 0 == anyhow::Context::with_context(count,|| format!("relay: {}",$addr))?{
                        break;
                    }
                    futures::sink::SinkExt::send(&mut $framed, &$buff).await?;
                    bytes::BytesMut::clear(&mut $buff);
                }
                res = futures::stream::StreamExt::next(&mut $framed) => {
                    match res.transpose()?{
                        Some(msg) => tokio::io::AsyncWriteExt::write_all(&mut $plain, &msg).await?,
                        None => break,
                    }
                }
                _ = tokio::time::sleep($crate::RELAY_TIMEOUT) => {
                    anyhow::bail!(format!("timeout: {}",$addr))
                }
            }
        }
        Ok(())
    }};
}
