use anyhow::{Context, Result};
use bytes::Buf;
use bytes::BytesMut;
use clap::Parser;
use futures::sink::SinkExt;
use ssrust::{Cipher, CryptoCodec, Method, NotEnoughBytesError, BUFFER_SIZE, DIAL_TIMEOUT};
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{self, TcpListener, TcpStream};
use tokio::time;
use tokio_util::codec::Decoder;
use tracing_subscriber::EnvFilter;

const NO_AUTHENTICATION: [u8; 2] = [5, 0];

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// remote shadowsocks server address
    #[arg(short, long)]
    remote_addr: String,
    /// local socks5 server address
    #[arg(long, default_value = "localhost:1080")]
    local_addr: String,
    #[arg(long)]
    password: String,
    #[arg(long, value_enum)]
    method: Method,
}

static REMOTE_ADDRS: OnceLock<Vec<SocketAddr>> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .compact()
        .with_target(false)
        .init();

    let args = Args::parse();
    Cipher::init(args.method, &args.password);
    let addrs = net::lookup_host(args.remote_addr).await?.collect();
    REMOTE_ADDRS.set(addrs).expect("set remote address failed");
    let listener = TcpListener::bind(args.local_addr).await?;
    ssrust::listen!(listener)
}

async fn process(mut client: TcpStream) -> Result<()> {
    client.set_nodelay(true)?;
    let mut buff = BytesMut::with_capacity(BUFFER_SIZE);

    // method selection
    client.read_buf(&mut buff).await?;
    client.write_all(&NO_AUTHENTICATION).await?;
    buff.clear();

    // reuse request packet
    client.read_buf(&mut buff).await?;
    anyhow::ensure!(buff.len() >= 2, NotEnoughBytesError::new(2, buff.len()));
    buff[1] = 0;
    client.write_all(&buff).await?;

    // reuse request address
    buff.advance(3);
    client.read_buf(&mut buff).await?;

    let (addr, _, _) = ssrust::parse_address(&buff)?;
    tracing::debug!("connect: {addr}");

    let addrs = REMOTE_ADDRS.get().expect("uninitialized").as_slice();
    let res = time::timeout(DIAL_TIMEOUT, TcpStream::connect(addrs)).await;
    let remote = ssrust::flatten(res).with_context(|| "remote unreachable")?;
    remote.set_nodelay(true)?;

    let mut remote = CryptoCodec::new().framed(remote);
    remote.send(&buff).await?;
    buff.clear();

    ssrust::relay!(client, remote, addr, buff)
}
