use anyhow::Result;
use bytes::{Buf, BytesMut};
use clap::Parser;
use ssrust::{Address, BUFFER_SIZE, Cipher, CryptoCodec, DIAL_TIMEOUT, Method};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{self, TcpListener, TcpStream};
use tokio::{signal, time};
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .compact()
        .with_target(false)
        .init();

    let args = Args::parse();

    let cipher = Arc::new(Cipher::init(&args.method, &args.password));
    let addrs: Arc<Vec<SocketAddr>> = Arc::new(net::lookup_host(args.remote_addr).await?.collect());
    let listener = TcpListener::bind(args.local_addr).await?;
    tracing::info!("listening on: {}", listener.local_addr().unwrap());
    loop {
        tokio::select! {
            res = listener.accept() => {
                if let Ok((client, _)) = res {
                    let addrs = addrs.clone();
                    let cipher = cipher.clone();
                    tokio::spawn(async move {
                        if let Err(e) = process(client, addrs, cipher).await {
                            tracing::error!("{:#}", e);
                        }
                    });
                }
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }
    Ok(())
}

async fn process(
    mut client: TcpStream,
    server: Arc<Vec<SocketAddr>>,
    cipher: Arc<Cipher>,
) -> Result<()> {
    client.set_nodelay(true)?;
    let mut buff = BytesMut::with_capacity(BUFFER_SIZE);

    // method selection
    client.read_buf(&mut buff).await?;
    client.write_all(&NO_AUTHENTICATION).await?;
    buff.clear();

    // reuse request packet
    client.read_buf(&mut buff).await?;
    buff[1] = 0;
    client.write_all(&buff).await?;

    // reuse request address
    buff.advance(3);

    let (addr, _) = Address::parse(&buff)?;
    tracing::debug!("connecting: {addr}");

    let remote = time::timeout(DIAL_TIMEOUT, TcpStream::connect(&server[..]))
        .await
        .map_err(|_| anyhow::anyhow!("connect server failed timeout"))?
        .map_err(|e| anyhow::anyhow!("connect server failed: {e}"))?;

    remote.set_nodelay(true)?;
    let mut remote = CryptoCodec::new(&cipher).framed(remote);

    ssrust::relay_with_buf(&mut client, &mut remote, &mut buff, &addr).await
}
