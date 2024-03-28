use std::{
    future::Future,
    io::Error,
    task::{ready, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use md5::Context;
use ring::{
    aead::{
        Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
        MAX_TAG_LEN,
    },
    hkdf::{Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, HKDF_SHA256},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
const MAX_PACKET_SIZE: usize = 0x3fff;


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

#[test]
fn test_derive_key() {
    let res = derive_key("barfoo!", 32);
    assert_eq!(
        res,
        [
            179, 173, 196, 120, 57, 224, 71, 235, 34, 136, 112, 82, 109, 200, 252, 48, 179, 71, 40,
            127, 252, 163, 4, 93, 206, 160, 107, 63, 223, 9, 10, 203
        ]
    );
}

const INFO: [&[u8]; 1] = [b"ss-subkey"];
pub fn hkdf_sha1(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = salt.extract(ikm);
    let okm = prk.expand(&INFO, HKDF_SHA256).unwrap();
    let mut res = vec![0u8; 32];
    okm.fill(&mut res).unwrap();
    res.truncate(ikm.len());
    res
}

#[test]
fn test_hkdf_sha1() {
    let salt = [0u8; 32];
    let ikm = derive_key("barfoo!", 32);
    let okm = hkdf_sha1(&salt, &ikm);
    assert_eq!(
        okm,
        [
            43, 141, 47, 153, 161, 146, 48, 46, 246, 13, 184, 49, 0, 9, 193, 126, 114, 1, 183, 184,
            193, 237, 33, 38, 2, 41, 108, 207, 99, 51, 1, 187
        ]
    );
}

const NONCE_SIZE: usize = 12;
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
        self.inc();
        Nonce::try_assume_unique_for_key(&self.0)
    }
}

pub struct StreamWrapper<'a> {
    stream: TcpStream,
    alogrithm: &'static Algorithm,
    master_key: &'a [u8],
    read_buffer: BytesMut,
    opening_key: Option<OpeningKey<NumeralNonce>>,
    sealing_key: Option<SealingKey<NumeralNonce>>,
}

impl <'a> StreamWrapper<'a> {
    pub fn new(
        stream: TcpStream,
        alogrithm: &'static Algorithm,
        master_key: &'a [u8],
    ) -> StreamWrapper<'a> {
        StreamWrapper {
            stream,
            alogrithm,
            master_key,
            opening_key: None,
            sealing_key: None,
            read_buffer: BytesMut::with_capacity(1024),
        }
    }
}

impl <'a> AsyncRead for StreamWrapper<'a> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let fut = this.stream.read_buf(&mut this.read_buffer);
        tokio::pin!(fut);
        if let std::task::Poll::Ready(res) = fut.poll(cx) {
            let n = res?;
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.opening_key.is_none() {
                let salt_size = this.alogrithm.key_len();
                if this.read_buffer.remaining() < salt_size {
                    return Poll::Pending;
                }
                let key_bytes = hkdf_sha1(&this.read_buffer[..salt_size], &this.master_key);
                this.read_buffer.advance(salt_size);
                let unbound_key = UnboundKey::new(this.alogrithm, &key_bytes).unwrap();
                this.opening_key = Some(OpeningKey::new(unbound_key, NumeralNonce::new()));
            }

            assert!(this.opening_key.is_some());

            let key = this.opening_key.as_mut().unwrap();
            let mut count = 0;
            loop {
                let n = this.read_buffer.remaining();
                if n < 2 + MAX_TAG_LEN {
                    break;
                }
                key.open_in_place(Aad::empty(), &mut this.read_buffer[..(2 + MAX_TAG_LEN)])
                    .map_err(|_| Error::other("fail to decrypt length"))?;
                let length = (this.read_buffer[0] as usize) << 8 | this.read_buffer[1] as usize;
                if n < 2 + length + 2 * MAX_TAG_LEN {
                    break;
                }
                this.read_buffer.advance(2 + MAX_TAG_LEN);
                key.open_in_place(
                    Aad::empty(),
                    &mut this.read_buffer[..(length + MAX_TAG_LEN)],
                )
                .map_err(|_| Error::other("fail to decryption payload"))?;
                buf.put_slice(&this.read_buffer[..length]);
                this.read_buffer.advance(length + MAX_TAG_LEN);
                count += length;
            }
            if count > 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        } else {
            Poll::Pending
        }
    }
}

impl <'a> AsyncWrite for StreamWrapper<'a> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let q = buf.len() / MAX_PACKET_SIZE;
        let r = buf.len() % MAX_PACKET_SIZE;
        let n = if r == 0 { q } else { q + 1 };
        let real_length = buf.len() + n * (2 + 2 * MAX_TAG_LEN);
        let mut local_buf = BytesMut::with_capacity(real_length);
        if this.sealing_key.is_none() {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut salt = vec![0u8; this.alogrithm.key_len()];
            SystemRandom::new().fill(&mut salt).unwrap();
            local_buf.put_slice(&salt);
            let okm = hkdf_sha1(&salt, &this.master_key);
            let unbound_key = UnboundKey::new(this.alogrithm, &okm).unwrap();
            this.sealing_key = Some(SealingKey::new(unbound_key, NumeralNonce::new()));
        }
        assert!(this.sealing_key.is_some());
        let key = this.sealing_key.as_mut().unwrap();

        for i in 0..n {
            let length = if i < n - 1 { MAX_PACKET_SIZE } else { r };
            local_buf.put_u16(length as u16);
            let last_two_bytes = local_buf.remaining() - 2;
            let tag = key
                .seal_in_place_separate_tag(Aad::empty(), &mut local_buf[last_two_bytes..])
                .unwrap();
            local_buf.put_slice(tag.as_ref());
            let index = i * MAX_PACKET_SIZE;
            local_buf.put_slice(&buf[index..(index + length)]);
            let payload_start = local_buf.remaining() - length;
            let tag = key
                .seal_in_place_separate_tag(Aad::empty(), &mut local_buf[payload_start..])
                .unwrap();
            local_buf.put_slice(tag.as_ref());
        }
        let fut = this.stream.write_all_buf(&mut local_buf);
        tokio::pin!(fut);
        ready!(fut.poll(cx))?;
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
