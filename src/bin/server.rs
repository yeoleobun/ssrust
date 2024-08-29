use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use ssrust::{Address, Cipher, CryptoCodec, Method, DIAL_TIMEOUT};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{self, TcpListener, TcpStream};
use tokio::time;
use tokio_util::codec::Decoder;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8388")]
    address: String,
    #[arg(long)]
    password: String,
    #[arg(long, value_enum)]
    method: Method,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .compact()
        .with_target(false)
        .init();

    let args = Args::parse();
    Cipher::init(args.method, &args.password);

    let listener = TcpListener::bind(args.address).await?;
    ssrust::listen!(listener)
}

async fn process(client: TcpStream) -> Result<()> {
    client.set_nodelay(true)?;
    let mut client = CryptoCodec::new().framed(client);

    let msg = match client.next().await.transpose()? {
        Some(bytes) => bytes,
        None => return Ok(()),
    };

    let (addr, port, rest) = ssrust::parse_address(&msg)?;
    tracing::debug!("connect: {addr}");

    let addrs = match &addr {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Address::Domain(host) => net::lookup_host(format!("{host}:{port}")).await?.collect(),
    };

    let mut remote =
        ssrust::flatten(time::timeout(DIAL_TIMEOUT, TcpStream::connect(addrs.as_slice())).await)
            .with_context(|| format!("connect: {addr}"))?;
    remote.set_nodelay(true)?;

    remote.write_all(rest).await?;
    drop(msg);

    ssrust::relay!(remote, client, addr)
}
