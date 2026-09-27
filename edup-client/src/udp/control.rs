//! Native Linux cmsghdr / Winsock CMSGHDR layout and alignment. No references
//! into possibly unaligned cmsg storage escape this module.
use super::invalid;
use std::{
    io,
    mem::{align_of, size_of},
    ptr,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    len: usize,
    level: i32,
    kind: i32,
}
const fn align(n: usize) -> usize {
    (n + align_of::<usize>() - 1) & !(align_of::<usize>() - 1)
}
const HEADER: usize = align(size_of::<Header>());

pub struct Control([usize; 32]);
impl Control {
    pub fn new() -> Self {
        Self([0; 32])
    }
    pub fn capacity(&self) -> usize {
        size_of::<Self>()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr().cast()
    }
    pub fn encode(&mut self, level: i32, kind: i32, value: &[u8]) -> usize {
        let len = HEADER + value.len();
        assert!(align(len) <= self.capacity());
        // SAFETY: storage is aligned for Header, initialized, and large enough.
        unsafe {
            ptr::write(self.as_mut_ptr().cast(), Header { len, level, kind });
            ptr::copy_nonoverlapping(value.as_ptr(), self.as_mut_ptr().add(HEADER), value.len());
        }
        align(len)
    }
    pub fn segment(&self, len: usize, level: i32, kind: i32) -> io::Result<Option<usize>> {
        if len > self.capacity() {
            return Err(invalid("oversized UDP control buffer"));
        }
        let mut offset = 0;
        let mut result = None;
        while len - offset >= size_of::<Header>() {
            // SAFETY: bounds checked above; unaligned reads also work on 32-bit.
            let header = unsafe {
                ptr::read_unaligned(self.0.as_ptr().cast::<u8>().add(offset).cast::<Header>())
            };
            if header.len < HEADER || header.len > len - offset {
                return Err(invalid("malformed UDP control header"));
            }
            if header.level == level && header.kind == kind {
                // Both UDP_GRO and UDP_COALESCED_INFO return a native u32.
                if header.len != HEADER + size_of::<u32>() || result.is_some() {
                    return Err(invalid("malformed UDP segment metadata"));
                }
                let value = unsafe {
                    ptr::read_unaligned(
                        self.0
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + HEADER)
                            .cast::<u32>(),
                    )
                };
                result = Some(value as usize);
            }
            let step = align(header.len);
            if step > len - offset {
                break;
            }
            offset += step;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_bounds_and_unknown_messages() {
        let mut c = Control::new();
        let n = c.encode(17, 104, &1200u32.to_ne_bytes());
        assert_eq!(c.segment(n, 17, 104).unwrap(), Some(1200));
        assert_eq!(c.segment(n, 17, 3).unwrap(), None);
        assert!(c.segment(HEADER + 3, 17, 104).is_err());
        assert!(c.segment(c.capacity() + 1, 17, 104).is_err());
        let n = c.encode(17, 104, &1200u16.to_ne_bytes());
        assert!(c.segment(n, 17, 104).is_err());
        c.0[0] = 0;
        assert!(c.segment(n, 17, 104).is_err());
    }
}
