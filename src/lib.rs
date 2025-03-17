use std::time::Duration;
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

mod cipher;
mod codec;
mod conn;

pub use cipher::{Cipher, Method};
pub use codec::CryptoCodec;
pub use conn::{Address, relay, relay_with_buf};
