use std::num::ParseIntError;

pub fn parse_u32(text: &str) -> Result<u32, ParseIntError> {
    if let Some(hex) = text.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        u32::from_str_radix(text, 10)
    }
}
