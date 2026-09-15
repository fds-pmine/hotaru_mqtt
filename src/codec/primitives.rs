//! Length-prefixed string / byte-slice readers and writers.

use std::sync::Arc;

use bytes::Bytes;

use crate::error::{CodecError, MqttError};


pub(super) fn read_u16(body: &[u8], cursor: &mut usize) -> Result<u16, MqttError> {
    if *cursor + 2 > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let v = u16::from_be_bytes([body[*cursor], body[*cursor + 1]]);
    *cursor += 2;
    Ok(v)
}

pub(super) fn read_arc_str(body: &[u8], cursor: &mut usize) -> Result<Arc<str>, MqttError> {
    let len = read_u16(body, cursor)? as usize;
    if *cursor + len > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let bytes = &body[*cursor..*cursor + len];
    let s = std::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)?;
    let result: Arc<str> = Arc::from(s);
    *cursor += len;
    Ok(result)
}

pub(super) fn read_bytes(body: &[u8], cursor: &mut usize) -> Result<Bytes, MqttError> {
    let len = read_u16(body, cursor)? as usize;
    if *cursor + len > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let v = body[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(Bytes::from(v))
}

pub(super) fn write_arc_str(out: &mut Vec<u8>, s: &Arc<str>) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

pub(super) fn write_bytes(out: &mut Vec<u8>, b: &Bytes) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(&b[..]);
}
