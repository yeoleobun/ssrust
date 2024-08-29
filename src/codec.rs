use crate::cipher::{Cipher, Counter};
use anyhow::{Error, Result};
use bytes::BufMut;
use bytes::BytesMut;
use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, MAX_TAG_LEN};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Default)]
pub struct CryptoCodec {
    opening_key: Option<OpeningKey<Counter>>,
    sealing_key: Option<SealingKey<Counter>>,
    payload_length: Option<usize>,
}

impl CryptoCodec {
    pub fn new() -> CryptoCodec {
        CryptoCodec::default()
    }
}
impl Encoder<&[u8]> for CryptoCodec {
    type Error = Error;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<()> {
        let sealing_key = match self.sealing_key.as_mut() {
            Some(k) => k,
            None => {
                let (sub_key, salt) = Cipher::session_key()?;
                dst.put_slice(salt.as_slice());
                self.sealing_key
                    .insert(SealingKey::new(sub_key, Counter::zero()))
            }
        };

        // total length = 2 + TAG + length + TAG
        dst.reserve(item.len() + 2 + 2 * MAX_TAG_LEN);

        //encrypt length
        dst.put_u16(item.len() as u16);
        let mut tail = dst.split_off(dst.len() - 2);
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut tail)?;
        dst.unsplit(tail);

        //encrypt payload
        dst.put_slice(item);
        let mut tail = dst.split_off(dst.len() - item.len());
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut tail)?;
        dst.unsplit(tail);
        Ok(())
    }
}

impl Decoder for CryptoCodec {
    type Item = BytesMut;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        let opening_key = match self.opening_key.as_mut() {
            Some(key) => key,
            None => {
                let salt_size = Cipher::salt_len();
                if src.len() < salt_size {
                    return Ok(None);
                }
                let sub_key = Cipher::session_key_with_salt(&src.split_to(salt_size))?;
                self.opening_key
                    .insert(OpeningKey::new(sub_key, Counter::zero()))
            }
        };

        //decrypt length
        let length = match self.payload_length {
            Some(n) => n,
            None => {
                if src.len() < 2 + MAX_TAG_LEN {
                    src.reserve(2 + MAX_TAG_LEN - src.len());
                    return Ok(None);
                }
                let mut header = src.split_to(2 + MAX_TAG_LEN);
                opening_key.open_in_place(Aad::empty(), &mut header)?;
                use bytes::Buf;
                *self.payload_length.insert(header.get_u16() as usize)
            }
        };

        //decrypt payload
        if src.len() < length + MAX_TAG_LEN {
            src.reserve(length + MAX_TAG_LEN - src.len());
            return Ok(None);
        }

        self.payload_length = None;
        let mut payload = src.split_to(length + MAX_TAG_LEN);
        opening_key.open_in_place(Aad::empty(), &mut payload)?;
        payload.truncate(length);
        Ok(Some(payload))
    }
}
