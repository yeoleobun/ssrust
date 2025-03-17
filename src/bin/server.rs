use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use ssrust::{Address, Cipher, CryptoCodec, DIAL_TIMEOUT, Method};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::{signal, time};
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

    let cipher = Arc::new(Cipher::init(&args.method, &args.password));
    let listener = TcpListener::bind(args.address).await?;
    tracing::info!("listening on: {}", listener.local_addr().unwrap());
    loop {
        tokio::select! {
            res = listener.accept() => {
                if let Ok((client, _)) = res {
                    let cipher = cipher.clone();
                    tokio::spawn(async move {
                        if let Err(e) = process(client, cipher).await {
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

async fn process(client: TcpStream, cipher: Arc<Cipher>) -> Result<()> {
    client.set_nodelay(true)?;
    let mut client = CryptoCodec::new(&cipher).framed(client);

    let msg = match client.next().await.transpose()? {
        Some(bytes) => bytes,
        None => return Ok(()),
    };

    let (addr, rest) = Address::parse(&msg)?;
    let socket_addrs = addr.to_socket_addrs()?;
    let connect_future = TcpStream::connect(socket_addrs.as_slice());
    let mut remote = match time::timeout(DIAL_TIMEOUT, connect_future).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::warn!("connect {addr} failed {:#}", e);
            return Ok(());
        }
        Err(_) => {
            tracing::warn!("connect {addr} timeout");
            return Ok(());
        }
    };

    tracing::debug!("{addr}: connected");
    remote.set_nodelay(true)?;
    if rest.len() > 0 {
        remote.write_all(rest).await?;
    }
    drop(msg);

    ssrust::relay(&mut remote, &mut client, &addr).await
}
