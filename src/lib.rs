use bytes::{Buf, BufMut, BytesMut};
use clap::ValueEnum;
use md5::Context;
use ring::{
    aead::{Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey},
    hkdf::{Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, HKDF_SHA256},
};
use ring::{
    aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    cmp::min,
    fmt::Display,
    future::Future,
    io::{self, Cursor, Error},
    net::{Ipv4Addr, Ipv6Addr},
    task::{ready, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    select,
};
use tracing::{debug, instrument, Level};

const MAX_PAYLOAD_SIZE: usize = 0x3fff;
const NONCE_SIZE: usize = 12;
const TAG_LEN: usize = 16;
const INFO: [&[u8]; 1] = [b"ss-subkey"];

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Method {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl From<Method> for &'static Algorithm {
    fn from(method: Method) -> Self {
        match method {
            Method::AES_128_GCM => &AES_128_GCM,
            Method::AES_256_GCM => &AES_256_GCM,
            Method::CHACHA20_POLY1305 => &CHACHA20_POLY1305,
        }
    }
}

pub fn derive_key(password: &str, len: usize) -> Vec<u8> {
    assert!(len % 16 == 0);
    let mut result = Vec::with_capacity(len);
    let mut pre = md5::compute(password);
    result.extend(<[u8; 16]>::from(pre));
    for _ in 1..(len / 16) {
        let mut ctx = Context::new();
        ctx.consume(<[u8; 16]>::from(pre));
        ctx.consume(password);
        pre = ctx.compute();
        result.extend(<[u8; 16]>::from(pre));
    }
    result
}

fn hkdf_sha1(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = salt.extract(ikm);
    let okm = prk.expand(&INFO, HKDF_SHA256).unwrap();
    let mut res = vec![0u8; 32];
    okm.fill(&mut res).unwrap();
    res.truncate(ikm.len());
    res
}

struct NumeralNonce([u8; NONCE_SIZE]);

impl NumeralNonce {
    fn new() -> NumeralNonce {
        NumeralNonce([0u8; NONCE_SIZE])
    }

    fn inc(&mut self) {
        let mut carry = 1;
        for i in &mut self.0 {
            let j = carry + (*i) as u32;
            *i = j as u8;
            carry = j >> 8;
        }
    }
}

impl NonceSequence for NumeralNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let res = Nonce::try_assume_unique_for_key(&self.0);
        self.inc();
        res
    }
}

pub struct EncryptWrapper {
    stream: TcpStream,
    alogrithm: &'static Algorithm,
    master_key: Vec<u8>,
    opening_key: Option<OpeningKey<NumeralNonce>>,
    sealing_key: Option<SealingKey<NumeralNonce>>,
    payload_length: Option<u16>,
    text: BytesMut,
    raw: BytesMut,
    write_buf: BytesMut,
}

impl EncryptWrapper {
    pub fn new(
        stream: TcpStream,
        alogrithm: &'static Algorithm,
        master_key: Vec<u8>,
    ) -> EncryptWrapper {
        EncryptWrapper {
            stream,
            alogrithm,
            master_key,
            opening_key: None,
            sealing_key: None,
            payload_length: None,
            text: BytesMut::with_capacity(8192),
            raw: BytesMut::with_capacity(8192),
            write_buf: BytesMut::with_capacity(8192),
        }
    }
}

fn fill(
    cx: &mut std::task::Context<'_>,
    stream: &mut TcpStream,
    buf: &mut BytesMut,
    n: usize,
) -> std::task::Poll<std::io::Result<bool>> {
    buf.reserve(n - buf.remaining());
    let mut ret = 1;
    while buf.remaining() < n && ret > 0 {
        let fut = stream.read_buf(buf);
        tokio::pin!(fut);
        ret = ready!(fut.poll(cx))?;
    }
    Poll::Ready(Ok(buf.remaining() < n))
}

impl AsyncRead for EncryptWrapper {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.text.has_remaining() {
            let n = min(buf.remaining(), this.text.remaining());
            buf.put_slice(&this.text[..n]);
            this.text.advance(n);
            return Poll::Ready(Ok(()));
        }

        // derive session key
        if this.opening_key.is_none() {
            let salt_size = this.alogrithm.key_len();
            if ready!(fill(cx, &mut this.stream, &mut this.raw, salt_size))? {
                return Poll::Ready(Ok(()));
            }

            let key_bytes = hkdf_sha1(&this.raw[..salt_size], &this.master_key);
            let unbound_key = UnboundKey::new(this.alogrithm, &key_bytes).expect("wrong key size");
            this.opening_key = Some(OpeningKey::new(unbound_key, NumeralNonce::new()));
            this.raw.advance(salt_size);
        }

        let key = this.opening_key.as_mut().unwrap();
        let mut count = 0;

        loop {
            // decrypt payload
            if let Some(n) = this.payload_length {
                let n = n as usize;
                if this.raw.remaining() < n + TAG_LEN {
                    if count > 0 {
                        return Poll::Ready(Ok(()));
                    }

                    if ready!(fill(cx, &mut this.stream, &mut this.raw, n + TAG_LEN))? {
                        return Poll::Ready(Ok(()));
                    }
                }

                key.open_in_place(Aad::empty(), &mut this.raw[..n + TAG_LEN])
                    .map_err(|_| Error::other("decryption fail"))?;
                let m = min(n, buf.remaining());
                buf.put_slice(&this.raw[..m]);
                this.text.put_slice(&this.raw[m..n]);
                this.raw.advance(n + TAG_LEN);
                this.payload_length = None;

                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                count += m;
            } else {
                // decrypt length
                if this.raw.remaining() < 2 + TAG_LEN {
                    if count > 0 {
                        return Poll::Ready(Ok(()));
                    }

                    if ready!(fill(cx, &mut this.stream, &mut this.raw, 2 + TAG_LEN))? {
                        return Poll::Ready(Ok(()));
                    }
                }
                key.open_in_place(Aad::empty(), &mut this.raw[..2 + TAG_LEN])
                    .map_err(|_| Error::other("decryption fail"))?;
                let n = this.raw.get_u16();
                this.raw.advance(TAG_LEN);
                this.payload_length = Some(n);
            }
        }
    }
}

impl AsyncWrite for EncryptWrapper {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();

        if this.sealing_key.is_none() {
            let mut salt = vec![0u8; this.alogrithm.key_len()];
            SystemRandom::new()
                .fill(&mut salt)
                .expect("generateing salt error");
            this.write_buf.put_slice(&salt);
            let okm = hkdf_sha1(&salt, &this.master_key);
            let unbound_key = UnboundKey::new(this.alogrithm, &okm).expect("illegal key length");
            this.sealing_key = Some(SealingKey::new(unbound_key, NumeralNonce::new()));
        }

        let key = this.sealing_key.as_mut().unwrap();
        let mut cursor = Cursor::new(buf);

        while cursor.has_remaining() {
            let length = min(MAX_PAYLOAD_SIZE, cursor.remaining());
            this.write_buf.reserve(length + 2 + 2 * TAG_LEN);

            // encrypt length
            this.write_buf.put_u16(length as u16);
            let last_2 = this.write_buf.remaining() - 2;
            let length_tag = key
                .seal_in_place_separate_tag(Aad::empty(), &mut this.write_buf[last_2..])
                .map_err(|_| Error::other("encrypt length error"))?;
            this.write_buf.put_slice(length_tag.as_ref());

            //encrypt payload
            this.write_buf.put_slice(&cursor.chunk()[..length]);
            let last_n = this.write_buf.remaining() - length;
            let payload_tag = key
                .seal_in_place_separate_tag(Aad::empty(), &mut this.write_buf[last_n..])
                .expect("encryption pyaload error");
            this.write_buf.put_slice(payload_tag.as_ref());

            let fut = this.stream.write_all_buf(&mut this.write_buf);
            tokio::pin!(fut);
            ready!(fut.poll(cx))?;

            cursor.advance(length);
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let fut = self.get_mut().stream.flush();
        tokio::pin!(fut);
        fut.poll(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let fut = self.get_mut().stream.shutdown();
        tokio::pin!(fut);
        fut.poll(cx)
    }
}

#[derive(Debug)]
pub enum Addr {
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

pub fn parse_address(buf: &[u8]) -> (Addr, u16, &[u8]) {
    assert!(buf.len() >= 7);
    match buf[0] {
        1 => {
            let ip = u32::from_be_bytes((&buf[1..5]).try_into().unwrap());
            let port = u16::from_be_bytes((&buf[5..7]).try_into().unwrap());
            (Addr::Ipv4(ip.into()), port, &buf[7..])
        }
        3 => {
            let length = buf[1] as usize;
            assert!(buf.len() >= length + 4);
            let domain = String::from_utf8_lossy(&buf[2..length + 2]).to_string();
            let port = u16::from_be_bytes((&buf[length + 2..length + 4]).try_into().unwrap());
            (Addr::Domain(domain), port, &buf[length + 4..])
        }
        4 => {
            assert!(buf.len() >= 19);
            let ip = u128::from_be_bytes((&buf[1..17]).try_into().unwrap());
            let port = u16::from_be_bytes((&buf[17..19]).try_into().unwrap());
            (Addr::Ipv6(ip.into()), port, &buf[19..])
        }
        _ => panic!("invalid address"),
    }
}

pub async fn connect(addr: &Addr, port: u16) -> std::io::Result<TcpStream> {
    match addr {
        Addr::Ipv4(ip) => TcpStream::connect((*ip, port)).await,
        Addr::Ipv6(ip) => TcpStream::connect((*ip, port)).await,
        Addr::Domain(host) => TcpStream::connect((host.as_ref(), port)).await,
    }
}

pub fn serialize(addr: &Addr, port: u16) -> Vec<u8> {
    let mut res = Vec::new();
    match addr {
        Addr::Ipv4(ip) => {
            res.put_u8(1);
            res.put_slice(&ip.octets());
        }
        Addr::Ipv6(ip) => {
            res.put_u8(4);
            res.put_slice(&ip.octets());
        }
        Addr::Domain(hostname) => {
            res.put_u8(3);
            res.put_u8(hostname.len() as u8);
            res.put_slice(hostname.as_bytes());
        }
    }
    res.put_u16(port);
    res
}

#[instrument(level = Level::TRACE, skip(client, remote), ret)]
pub async fn relay<A, B>(client: &mut A, remote: &mut B, addr: &str) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
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
                debug!("timeout");
                break
            }
        }
    }
    Ok(())
}
