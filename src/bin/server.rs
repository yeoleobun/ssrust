use anyhow::anyhow;
use clap::{arg, Parser};
use futures::{SinkExt, StreamExt};
use ssrust::{parse_address, relay, Method};
use ssrust::{Addr, Config, CryptoCodec};
use std::io::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio::{net::TcpListener, signal};
use tokio_util::codec::Framed;
use tracing::{debug, error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version,about, long_about = None)]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    address: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    password: String,
    #[arg(long, value_enum)]
    method: Method,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let args = Args::parse();
    Config::init(args.method, &args.password);
    let listener = TcpListener::bind((args.address, args.port)).await?;

    loop {
        tokio::select! {
            result  = listener.accept() => {
                match result{
                    Ok((socket,_)) => {
                        tokio::spawn(process(socket));
                    },
                    Err(err) => {
                        error!("accept error: {err}");
                        break;
                    },
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutdown");
                break;
            }
        }
    }
    Ok(())
}

async fn process(client: TcpStream) -> anyhow::Result<()> {
    client.set_nodelay(true)?;
    let mut client = Framed::new(client, CryptoCodec::new());
    let mut buff = client
        .next()
        .await
        .transpose()
        .and_then(|op| op.ok_or(anyhow!("hehe")))?;

    // get remote address
    // client.read_buf(&mut buff).await?;
    let (addr, port, rest) = parse_address(&buff)?;
    debug!("connect: {addr}");

    let mut remote = match &addr {
        Addr::Ipv4(ip) => TcpStream::connect((*ip, port)).await,
        Addr::Ipv6(ip) => TcpStream::connect((*ip, port)).await,
        Addr::Domain(host) => TcpStream::connect((host.as_ref(), port)).await,
    }?;
    let _ = remote.set_nodelay(true);
    // maybe with payload
    if !rest.is_empty() {
        remote.write_all(rest).await?;
    }
    buff.clear();

    relay(remote, client, buff, addr).await
}
