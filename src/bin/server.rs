use bytes::BytesMut;
use clap::{arg, Parser, ValueEnum};
use ssrust::EncryptWrapper;
use std::fmt::Display;
use std::io::{self, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::select;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use tracing::{info, instrument, Level};
#[derive(Parser)]
#[command(version,about, long_about = None)]
struct Cli {
    #[arg(long)]
    address: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    password: String,
    #[arg(long, value_enum)]
    method: Method,
}

enum Addr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Ipv4(ip) => write!(f, "{}", ip),
            Addr::Ipv6(ip) => write!(f, "{}", ip),
            Addr::Domain(host) => write!(f, "{}", host),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Method {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    signal,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let cli = Cli::parse();

    let listener = TcpListener::bind((cli.address, cli.port)).await?;
    let master_key = ssrust::derive_key(&cli.password, 32);
    let algorithm = match cli.method {
        Method::AES_128_GCM => &AES_128_GCM,
        Method::AES_256_GCM => &AES_256_GCM,
        Method::CHACHA20_POLY1305 => &CHACHA20_POLY1305,
    };
    info!(address = ?listener.local_addr()?);

    loop {
        tokio::select! {
            result  = listener.accept() => {
                let (socket,_) = result?;
                socket.set_nodelay(true)?;
                let client = EncryptWrapper::new(socket,algorithm,master_key.clone());
                tokio::spawn(process(client));
            }
            _ = signal::ctrl_c() => break
        }
    }
    Ok(())
}

async fn process(mut client: EncryptWrapper) -> io::Result<()> {
    let (addr, port) = handshake(&mut client).await?;
    let address = format!("{}: {}", addr, port);
    let mut remote = match addr {
        Addr::Ipv4(ip) => TcpStream::connect((ip, port)).await?,
        Addr::Ipv6(ip) => TcpStream::connect((ip, port)).await?,
        Addr::Domain(host) => TcpStream::connect((host, port)).await?,
    };
    relay(&mut client, &mut remote, &address).await
}

async fn handshake(client: &mut EncryptWrapper) -> io::Result<(Addr, u16)> {
    let addr = match client.read_u8().await? {
        1 => {
            let ipv4 = client.read_u32().await?;
            Addr::Ipv4(Ipv4Addr::from(ipv4))
        }
        3 => {
            let n = client.read_u8().await?;
            let mut arr = vec![0u8; n as usize];
            client.read_exact(&mut arr).await?;
            Addr::Domain(String::from_utf8(arr).expect("invalid domain"))
        }
        4 => {
            let ipv6 = client.read_u128().await?;
            Addr::Ipv6(Ipv6Addr::from(ipv6))
        }
        _ => {
            return Err(Error::other("illegal address type"));
        }
    };
    let port = client.read_u16().await?;
    Ok((addr, port))
}

#[instrument(level = Level::TRACE, skip(client, remote), ret)]
async fn relay(client: &mut EncryptWrapper, remote: &mut TcpStream, addr: &str) -> io::Result<()> {
    let mut buf1 = BytesMut::with_capacity(4096);
    let mut buf2 = BytesMut::with_capacity(4096);
    loop {
        select! {
            res = client.read_buf(&mut buf1) => {
                if 0 == res?{
                    break
                }
                remote.write_all_buf(&mut buf1).await?
            }
            res = remote.read_buf(&mut buf2) => {
                if 0 == res?{
                    break
                }
                client.write_all_buf(&mut buf2).await?
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {
                return Err(Error::new(ErrorKind::TimedOut, "timeout"))
            }
        }
    }
    Ok(())
}
