use anyhow::Result;
use bytes::{Buf, BytesMut};
use clap::Parser;
use futures::{sink::SinkExt, StreamExt};
use ssrust::{parse_address, relay, Config, CryptoCodec, Method};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select, signal,
};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, Level};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

const NO_AUTHENTICATION: [u8; 2] = [5, 0];
#[derive(Parser)]
#[command(version,about, long_about = None)]
struct Args {
    #[arg(long)]
    server: String,
    #[arg(long)]
    server_port: u16,
    #[arg(long, default_value = "localhost")]
    local_address: String,
    #[arg(long)]
    local_port: u16,
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
    let listener = TcpListener::bind((args.local_address, args.local_port)).await?;
    loop {
        select! {
            res = listener.accept() => {
                match res{
                    Ok((client,_)) => {
                        match TcpStream::connect((args.server.as_ref(), args.server_port)).await{
                            Ok(remote) => {
                                tokio::spawn(process(client,remote));
                            },
                            Err(err) => error!("remote unreachable: {err}")
                        }
                    },
                    Err(err) => {
                        error!(?err);
                        break;
                    },
                }
            },
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }
    Ok(())
}

#[instrument(level = Level::TRACE, skip(client, remote), ret)]
async fn process(mut client: TcpStream, remote: TcpStream) -> Result<()> {
    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let mut remote = Framed::new(remote, CryptoCodec::new());
    let mut buff = BytesMut::with_capacity(8096);

    // method selection
    client.read_buf(&mut buff).await?;
    client.write_all(&NO_AUTHENTICATION).await?;
    buff.clear();

    // reuse request package
    client.read_buf(&mut buff).await?;
    buff[1] = 0;
    client.write_all(&buff).await?;

    // reuse address
    buff.advance(3);
    let (addr, _, _) = parse_address(&buff)?;
    debug!("connect: {addr}");

    // get frist request
    client.read_buf(&mut buff).await?;
    remote.send(&buff).await?;
    buff.clear();

    relay(client, remote, buff, addr).await
}
