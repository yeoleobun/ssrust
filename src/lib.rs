use std::{
    cmp::min,
    future::Future,
    io::{Cursor, Error},
    task::{ready, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use md5::Context;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{
    aead::{Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey},
    hkdf::{Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, HKDF_SHA256},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

const MAX_PAYLOAD_SIZE: usize = 0x3fff;
const NONCE_SIZE: usize = 12;
const TAG_LEN: usize = 16;
const INFO: [&[u8]; 1] = [b"ss-subkey"];

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
            text: BytesMut::with_capacity(4096),
            raw: BytesMut::with_capacity(4096),
            write_buf: BytesMut::with_capacity(4096),
        }
    }
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

        let fut = this.stream.read_buf(&mut this.raw);
        tokio::pin!(fut);
        if 0 == ready!(fut.poll(cx))? {
            return Poll::Ready(Ok(()));
        }

        // derive session key
        if this.opening_key.is_none() {
            let salt_size = this.alogrithm.key_len();
            if this.raw.remaining() < salt_size {
                return Poll::Pending;
            }
            let key_bytes = hkdf_sha1(&this.raw[..salt_size], &this.master_key);
            this.raw.advance(salt_size);
            let unbound_key = UnboundKey::new(this.alogrithm, &key_bytes).expect("wrong key size");
            this.opening_key = Some(OpeningKey::new(unbound_key, NumeralNonce::new()));
        }

        let key = this.opening_key.as_mut().unwrap();

        loop {
            // decrypt payload
            if let Some(n) = this.payload_length {
                let n = n as usize;
                if this.raw.remaining() < n + TAG_LEN {
                    break;
                }
                key.open_in_place(Aad::empty(), &mut this.raw[..n + TAG_LEN])
                    .map_err(|_| Error::other("decryption fail"))?;
                this.text.put_slice(&this.raw[..n]);
                this.raw.advance(n + TAG_LEN);
                this.payload_length = None;
            } else {
                // decrypt length
                if this.raw.remaining() < 2 + TAG_LEN {
                    break;
                }
                key.open_in_place(Aad::empty(), &mut this.raw[..2 + TAG_LEN])
                    .map_err(|_| Error::other("decryption fail"))?;
                let n = this.raw.get_u16();
                this.raw.advance(TAG_LEN);
                this.payload_length = Some(n);
            }
        }

        if this.text.remaining() == 0 {
            return Poll::Pending;
        }

        let n = min(buf.remaining(), this.text.remaining());
        buf.put_slice(&this.text[..n]);
        this.text.advance(n);
        Poll::Ready(Ok(()))
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
            cursor.advance(length);
        }

        let fut = this.stream.write_all_buf(&mut this.write_buf);
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
