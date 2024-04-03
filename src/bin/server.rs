use bytes::BytesMut;
use clap::{arg, Parser};
use ssrust::{connect, relay, EncryptWrapper};
use ssrust::{parse_address, Method};
use std::io::{self, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpListener, signal};
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version,about, long_about = None)]
struct Cli {
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

    let cli = Cli::parse();

    let listener = TcpListener::bind((cli.address, cli.port)).await?;
    let master_key = ssrust::derive_key(&cli.password, 32);
    let algorithm = cli.method.into();
    info!(listening = ?listener.local_addr()?);

    loop {
        tokio::select! {
            result  = listener.accept() => {
                if let Ok((socket,_)) = result{
                    let _ = socket.set_nodelay(true);
                    let client = EncryptWrapper::new(socket,algorithm,master_key.clone());
                    tokio::spawn(process(client));
                }else{
                    error!("accept error");
                }
            }
            _ = signal::ctrl_c() => break
        }
    }
    Ok(())
}

async fn process(mut client: EncryptWrapper) -> io::Result<()> {
    let mut buff = BytesMut::new();
    // get remote address
    client.read_buf(&mut buff).await?;
    let (addr, port, rest) = parse_address(&buff);
    let mut remote = connect(&addr, port).await?;
    let _ = remote.set_nodelay(true);
    // maybe with payload
    if !rest.is_empty() {
        remote.write_all(rest).await?;
    }
    relay(&mut client, &mut remote, &format!("{addr}: {port}")).await
}
