use bytes::{Buf, BytesMut};
use clap::Parser;
use ssrust::{parse_address, relay, EncryptWrapper, Method};
use std::io::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select, signal,
};
use tracing::{error, info};
use tracing_subscriber::{
    fmt::format::FmtSpan,
    EnvFilter,
};

const NO_AUTHENTICATION: [u8; 2] = [5, 0];
#[derive(Parser)]
#[command(version,about, long_about = None)]
struct Cli {
    #[arg(long)]
    server: String,
    #[arg(long)]
    server_port: u16,
    #[arg(long)]
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

    let cli = Cli::parse();
    let listener = TcpListener::bind((cli.local_address, cli.local_port)).await?;
    let master_key = ssrust::derive_key(&cli.password, 32);
    let algorithm = cli.method.into();
    info!(listening = ?listener.local_addr());
    loop {
        select! {
            res = listener.accept() => {
                if let Ok((client, _)) = res{
                    if let Ok(remote) = TcpStream::connect((cli.server.as_ref(), cli.server_port)).await{
                        let _ = client.set_nodelay(true);
                        let _ = remote.set_nodelay(true);
                        let remote = EncryptWrapper::new(remote,algorithm,master_key.clone());
                        tokio::spawn(process(client, remote));
                    }else{
                        error!("remote not available");
                    }
                }else{
                    error!("accept error");
                }
            },
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}

async fn process(mut client: TcpStream, mut remote: EncryptWrapper) -> Result<()> {
    let mut buff = BytesMut::new();

    // methods
    client.read_buf(&mut buff).await?;
    client.write_all(&NO_AUTHENTICATION).await?;
    buff.clear();

    // request
    client.read_buf(&mut buff).await?;
    buff[1] = 0;
    client.write_all(&buff).await?;

    buff.advance(3);
    let (addr, port, _) = parse_address(&buff).expect("illegal adress");

    // fill initial payload
    client.read_buf(&mut buff).await?;
    remote.write_all(&buff).await?;
    relay(&mut client, &mut remote, &format!("{addr}:{port}")).await
}
