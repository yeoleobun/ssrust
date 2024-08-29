use anyhow::Result;
use ring::aead::{Algorithm, Nonce, NonceSequence, UnboundKey};
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN};
use ring::error::Unspecified;
use ring::hkdf::{Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::OnceLock;

const INFO: [&[u8]; 1] = [b"ss-subkey"];
static CIPHER: OnceLock<Cipher> = OnceLock::new();

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Method {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl From<Method> for &'static Algorithm {
    fn from(value: Method) -> Self {
        match value {
            Method::AES_128_GCM => &AES_128_GCM,
            Method::AES_256_GCM => &AES_256_GCM,
            Method::CHACHA20_POLY1305 => &CHACHA20_POLY1305,
        }
    }
}

pub struct Counter([u8; NONCE_LEN]);

impl Counter {
    pub fn zero() -> Counter {
        Counter([0u8; NONCE_LEN])
    }
}

impl NonceSequence for Counter {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.0);
        let mut y = 1u32;
        for x in &mut self.0 {
            y += *x as u32;
            *x = y as u8;
            y >>= 8;
        }
        Ok(nonce)
    }
}

#[derive(Debug)]
pub struct Cipher {
    alogrithm: &'static Algorithm,
    master_key: Vec<u8>,
    rng: SystemRandom,
}

impl Cipher {
    pub fn init(method: Method, password: &str) {
        let alogrithm: &'static Algorithm = method.into();
        let config = Cipher {
            alogrithm,
            master_key: bytes_to_key(password, alogrithm.key_len()),
            rng: SystemRandom::new(),
        };
        CIPHER.set(config).expect("set cipher failed");
    }

    pub(crate) fn salt_len() -> usize {
        Cipher::get().alogrithm.key_len()
    }

    pub(crate) fn session_key() -> Result<(UnboundKey, Vec<u8>)> {
        let cipher = Cipher::get();
        let mut salt = vec![0u8; cipher.alogrithm.key_len()];
        cipher.rng.fill(&mut salt)?;
        let subkey = Cipher::session_key_with_salt(&salt)?;
        Ok((subkey, salt))
    }

    // hkdf-sha1, derivi session key from master key
    pub(crate) fn session_key_with_salt(salt: &[u8]) -> Result<UnboundKey> {
        let cipher = Cipher::get();
        let mut key_bytes = vec![0u8; 32];
        Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
            .extract(&cipher.master_key)
            .expand(&INFO, HKDF_SHA256)?
            .fill(&mut key_bytes)?;
        key_bytes.truncate(cipher.alogrithm.key_len());
        Ok(UnboundKey::new(cipher.alogrithm, &key_bytes)?)
    }

    fn get() -> &'static Cipher {
        CIPHER.get().expect("uninitialized")
    }
}

// EVP_BytesToKey, derive master key from password
fn bytes_to_key(password: &str, len: usize) -> Vec<u8> {
    let mut res = Vec::with_capacity(len);
    for _ in 0..(len / 16) {
        let mut ctx = md5::Context::new();
        ctx.consume(&res);
        ctx.consume(password);
        res.extend(*ctx.compute());
    }
    res
}
