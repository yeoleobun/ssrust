use anyhow::bail;
use bytes::{Buf, BufMut, BytesMut};
use clap::ValueEnum;
use futures::{sink::SinkExt, StreamExt};
use md5::Context;
use rand::RngCore;
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use ring::{
    aead::{
        Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
        MAX_TAG_LEN, NONCE_LEN,
    },
    hkdf::{Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, HKDF_SHA256},
};
use std::fmt::Display;
use std::time::Duration;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::debug;

const MAX_PAYLOAD_LEN: usize = 0x3fff;
const INFO: [&[u8]; 1] = [b"ss-subkey"];
const ZERO: NumeralNonce = NumeralNonce(0);
const TIME_OUT: Duration = std::time::Duration::from_secs(15);
static CONFIG: OnceLock<Config> = OnceLock::new();

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Method {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

pub struct Config {
    alogrithm: &'static Algorithm,
    master_key: Vec<u8>,
}

impl Config {
    pub fn init(method: Method, password: &str) {
        let alogrithm: &'static Algorithm = match method {
            Method::AES_128_GCM => &AES_128_GCM,
            Method::AES_256_GCM => &AES_256_GCM,
            Method::CHACHA20_POLY1305 => &CHACHA20_POLY1305,
        };

        let master_key = derive_key(password, alogrithm.key_len());
        let config = Config {
            alogrithm,
            master_key,
        };
        let _ = CONFIG.set(config);
    }

    fn get() -> &'static Config {
        CONFIG.get().unwrap()
    }
}

pub fn derive_key(password: &str, len: usize) -> Vec<u8> {
    let mut res = Vec::with_capacity(len);
    let mut pre = md5::compute(password);
    res.extend(&*pre);
    for _ in 1..(len / 16) {
        let mut ctx = Context::new();
        ctx.consume(&*pre);
        ctx.consume(password);
        pre = ctx.compute();
        res.extend(&*pre);
    }
    res
}

fn hkdf_sha1(salt: &[u8], ikm: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut okm = vec![0u8; 32];
    Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(ikm)
        .expand(&INFO, HKDF_SHA256)?
        .fill(&mut okm)?;
    okm.truncate(ikm.len());
    Ok(okm)
}

struct NumeralNonce(u128);

impl NonceSequence for NumeralNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let value = &self.0.to_le_bytes()[..NONCE_LEN];
        let nonce = Nonce::try_assume_unique_for_key(value)?;
        self.0 += 1;
        Ok(nonce)
    }
}
pub struct CryptoCodec {
    opening_key: Option<OpeningKey<NumeralNonce>>,
    sealing_key: Option<SealingKey<NumeralNonce>>,
    payload_length: Option<usize>,
}

impl CryptoCodec {
    pub fn new() -> CryptoCodec {
        CryptoCodec {
            opening_key: None,
            sealing_key: None,
            payload_length: None,
        }
    }
}

impl Encoder<&[u8]> for CryptoCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        let sealing_key = match self.sealing_key.as_mut() {
            Some(k) => k,
            None => {
                let config = Config::get();
                let mut salt = vec![0u8; config.alogrithm.key_len()];
                rand::thread_rng().fill_bytes(&mut salt);
                // SystemRandom::new().fill(&mut salt)?;
                dst.put_slice(&salt);
                let sub_key = hkdf_sha1(&salt, &config.master_key)?;
                let unbound_key = UnboundKey::new(config.alogrithm, &sub_key)?;
                let sealing_key = SealingKey::new(unbound_key, ZERO);
                self.sealing_key.insert(sealing_key)
            }
        };

        let total = item.len();
        let n = total.div_ceil(MAX_PAYLOAD_LEN);
        dst.reserve(total + n * (2 + 2 * MAX_TAG_LEN));
        for i in 0..n {
            let offset = i * MAX_PAYLOAD_LEN;
            let length = usize::min(total - offset, MAX_PAYLOAD_LEN);

            dst.put_u16(length as u16);
            let mut tail = dst.split_off(dst.len() - 2);
            sealing_key.seal_in_place_append_tag(Aad::empty(), &mut tail)?;
            dst.unsplit(tail);

            dst.put_slice(&item[offset..offset + length]);
            let mut tail = dst.split_off(dst.len() - length);
            sealing_key.seal_in_place_append_tag(Aad::empty(), &mut tail)?;
            dst.unsplit(tail);
        }
        Ok(())
    }
}

impl Decoder for CryptoCodec {
    type Item = BytesMut;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let opening_key = match self.opening_key.as_mut() {
            Some(key) => key,
            None => {
                let config = Config::get();
                let salt_size = config.alogrithm.key_len(); // same as key size
                if src.len() < salt_size {
                    return Ok(None);
                }
                let sub_key = hkdf_sha1(&src[..salt_size], &config.master_key)?;
                src.advance(salt_size);
                let unbound_key = UnboundKey::new(config.alogrithm, &sub_key)?;
                let opening_key = OpeningKey::new(unbound_key, ZERO);
                self.opening_key.insert(opening_key)
            }
        };

        let n = match self.payload_length {
            Some(n) => n,
            None => {
                if src.len() < 2 + MAX_TAG_LEN {
                    return Ok(None);
                }
                opening_key.open_in_place(Aad::empty(), &mut src[..2 + MAX_TAG_LEN])?;
                let n = src.get_u16() as usize;
                src.advance(MAX_TAG_LEN);
                *self.payload_length.insert(n)
            }
        };

        if src.len() < n + MAX_TAG_LEN {
            src.reserve(n + MAX_TAG_LEN - src.len());
            return Ok(None);
        }

        opening_key.open_in_place(Aad::empty(), &mut src[..n + MAX_TAG_LEN])?;
        let res = src.split_to(n);
        src.advance(MAX_TAG_LEN);
        self.payload_length.take();
        Ok(Some(res))
    }
}

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

pub fn parse_address(mut buf: &[u8]) -> anyhow::Result<(Addr, u16, &[u8])> {
    assert!(buf.len() >= 7);
    let addr = match buf.get_u8() {
        1 => Addr::Ipv4(buf.get_u32().into()),
        4 => Addr::Ipv6(buf.get_u128().into()),
        3 => {
            let n = buf.get_u8() as usize;
            Addr::Domain(String::from_utf8(buf.copy_to_bytes(n).to_vec())?)
        }
        _ => bail!("illegal address"),
    };
    let port = buf.get_u16();
    Ok((addr, port, buf))
}

pub async fn relay(
    mut plain: TcpStream,
    mut framed: Framed<TcpStream, CryptoCodec>,
    mut buff: BytesMut,
    addr: Addr,
) -> anyhow::Result<()>
where
{
    loop {
        select! {
            count = plain.read_buf(&mut buff) => {
                if 0 == count?{
                    break;
                }
                framed.send(&buff).await?;
                buff.clear();
            }
            res = framed.next() => {
                match res.transpose()?{
                    Some(msg) => plain.write_all(&msg).await?,
                    None => break,
                }
            }
            _ = tokio::time::sleep(TIME_OUT) => {
                debug!("timeout: {}",addr);
                break
            }
        }
    }

    framed.close().await
}
