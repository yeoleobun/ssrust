use clap::{arg, Parser, ValueEnum};
use ssrust::StreamWrapper;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
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

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Method {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}
use ring::aead::Algorithm;
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    signal,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let listener = TcpListener::bind((cli.address, cli.port)).await?;
    let master_key = ssrust::derive_key(&cli.password, 32);
    loop {
        tokio::select! {
            result  = listener.accept() => {
                let (socket,_) = result?;
                socket.set_nodelay(true)?;
                let algorithm = match cli.method{
                    Method::AES_128_GCM => &AES_128_GCM,
                    Method::AES_256_GCM => &AES_256_GCM,
                    Method::CHACHA20_POLY1305 => &CHACHA20_POLY1305
                };
                tokio::spawn(handshake(socket,algorithm,master_key.clone()));
            }
            _ = signal::ctrl_c() => break
        }
    }

    Ok(())
}

async fn handshake(
    client: TcpStream,
    algorithm: &'static Algorithm,
    master_key: Vec<u8>,
) -> io::Result<()> {
    let mut client = StreamWrapper::new(client, algorithm, &master_key);
    let mut remote = match client.read_u8().await? {
        1 => {
            let ipv4 = client.read_u32_le().await?;
            let addr = Ipv4Addr::from(ipv4);
            let port = client.read_u16().await?;
            TcpStream::connect((addr, port)).await?
        }
        3 => {
            let n = client.read_u8().await?;
            let mut arr = vec![0u8; n as usize];
            client.read_exact(&mut arr).await?;
            match std::str::from_utf8(&arr) {
                Ok(addr) => {
                    let port = client.read_u16().await?;
                    TcpStream::connect((addr, port)).await?
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "un support address",
                    ))
                }
            }
        }
        4 => {
            let ipv6 = client.read_u128().await?;
            let addr = Ipv6Addr::from(ipv6);
            let port = client.read_u16().await?;
            TcpStream::connect((addr, port)).await?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "un support address",
            ))
        }
    };
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}
