use std::num::ParseIntError;

pub fn parse_u32(text: &str) -> Result<u32, ParseIntError> {
    if let Some(hex) = text.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        u32::from_str_radix(text, 10)
    }
}

pub fn parse_u16(text: &str) -> Result<u16, ParseIntError> {
    if let Some(hex) = text.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        u16::from_str_radix(text, 10)
    }
}

pub fn parse_i32(text: &str) -> Result<i32, ParseIntError> {
    let (negative, value) = text.strip_prefix('-').map(|abs| (true, abs)).unwrap_or((false, text));
    let abs_value =
        if let Some(hex) = value.strip_prefix("0x") { i32::from_str_radix(hex, 16)? } else { i32::from_str_radix(value, 10)? };
    if negative {
        Ok(-abs_value)
    } else {
        Ok(abs_value)
    }
}
