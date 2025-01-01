pub trait FromSlice {
    fn from_le_slice(s: &[u8]) -> Self;
}

impl FromSlice for u32 {
    fn from_le_slice(s: &[u8]) -> Self {
        assert!(s.len() >= 4);
        u32::from_le_bytes([s[0], s[1], s[2], s[3]])
    }
}

impl FromSlice for u16 {
    fn from_le_slice(s: &[u8]) -> Self {
        assert!(s.len() >= 2);
        u16::from_le_bytes([s[0], s[1]])
    }
}
