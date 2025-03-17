use anyhow::Result;
use ring::aead::{
    AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305, NONCE_LEN, Nonce, NonceSequence,
    UnboundKey,
};
use ring::error::Unspecified;
use ring::hkdf::{HKDF_SHA1_FOR_LEGACY_USE_ONLY, Salt};

const INFO: [&[u8]; 1] = [b"ss-subkey"];

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Method {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl From<&Method> for &'static Algorithm {
    fn from(value: &Method) -> Self {
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
        let mut carry = 1u32;
        let mut i = 0;
        while i < NONCE_LEN && carry > 0 {
            carry += self.0[i] as u32;
            self.0[i] = carry as u8;
            carry >>= 8;
            i += 1;
        }
        Ok(nonce)
    }
}

#[derive(Debug)]
pub struct Cipher {
    algorithm: &'static Algorithm,
    master_key: Vec<u8>,
}

impl Cipher {
    pub fn init(method: &Method, password: &str) -> Cipher {
        let algorithm: &'static Algorithm = method.into();
        let master_key = Self::bytes_to_key(password, algorithm.key_len());
        Cipher {
            algorithm,
            master_key,
        }
    }

    pub(crate) fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    // hkdf-sha1, derivi session key from master key
    pub(crate) fn new_session_key(&self, salt: &[u8]) -> Result<UnboundKey> {
        let mut key_bytes = vec![0u8; self.key_len()];
        Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
            .extract(&self.master_key)
            .expand(&INFO, self.algorithm)?
            .fill(&mut key_bytes)?;
        Ok(UnboundKey::new(self.algorithm, &key_bytes)?)
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
}
