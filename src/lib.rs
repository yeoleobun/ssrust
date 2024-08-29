use std::{result, time::Duration};
use thiserror::Error;
pub const BUFFER_SIZE: usize = 4096;
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(30);
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Error, Debug)]
#[error("Not enough bytes in buffer. Expected {expected:?} bytes, but found {actual:?} bytes.")]
pub struct NotEnoughBytesError {
    expected: usize,
    actual: usize,
}

impl NotEnoughBytesError {
    pub fn new(expected: usize, actual: usize) -> Self {
        Self { expected, actual }
    }
}

pub fn flatten<T, E1, E2>(nested: result::Result<result::Result<T, E2>, E1>) -> anyhow::Result<T>
where
    E1: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
{
    let inner = nested?;
    let val = inner?;
    Ok(val)
}

mod cipher;
mod codec;
mod conn;

pub use cipher::{Cipher, Method};
pub use codec::CryptoCodec;
pub use conn::{parse_address, Address};
