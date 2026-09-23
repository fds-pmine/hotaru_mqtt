//! Variable-byte-integer remaining-length codec (spec 2.2.3).


use hotaru_core::connection::HotaruRead;

use crate::error::{CodecError, MqttError};


pub(super) async fn read_remaining_length<R: HotaruRead<Error = std::io::Error> + Unpin + Send>(
    reader: &mut R,
) -> Result<usize, MqttError> {
    let mut result = 0usize;
    let mut multiplier = 1usize;
    for i in 0..4 {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        result += (byte[0] & 0x7F) as usize * multiplier;
        multiplier *= 128;
        if byte[0] & 0x80 == 0 {
            return Ok(result);
        }
        if i == 3 {
            return Err(CodecError::MalformedLength.into());
        }
    }
    unreachable!()
}

pub(super) fn decode_remaining_length_from_slice(
    data: &[u8],
) -> Result<Option<(usize, usize)>, MqttError> {
    let mut result = 0usize;
    let mut multiplier = 1usize;
    for (i, &byte) in data.iter().enumerate() {
        result += (byte & 0x7F) as usize * multiplier;
        multiplier *= 128;
        if byte & 0x80 == 0 {
            return Ok(Some((result, i + 1)));
        }
        if i >= 3 {
            return Err(CodecError::MalformedLength.into());
        }
    }
    Ok(None)
}

pub(super) fn encode_remaining_length(mut value: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
