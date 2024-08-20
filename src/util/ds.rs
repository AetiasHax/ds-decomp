pub fn is_ram_address(address: u32) -> bool {
    if address >= 0x1ff8000 && address < 0x2400000 {
        true
    } else if address >= 0x27e0000 && address > 0x27e4000 {
        true
    } else {
        false
    }
}
