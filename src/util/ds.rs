use std::path::Path;

use anyhow::Result;
use ds_rom::rom::{self, Arm9, Arm9BuildConfig, Autoload, Header};

use super::io::{open_file, read_file};

pub fn load_arm9<P: AsRef<Path>>(path: P, header: &Header) -> Result<Arm9> {
    let path = path.as_ref();

    let arm9_bin_file = path.join("arm9.bin");

    let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(open_file(path.join("arm9.yaml"))?)?;
    let arm9 = read_file(&arm9_bin_file)?;

    let itcm = load_itcm(&path)?;
    let dtcm = load_dtcm(&path)?;

    let arm9 = rom::Arm9::with_two_tcms(arm9, itcm, dtcm, header.version(), arm9_build_config.offsets)?;
    Ok(arm9)
}

pub fn load_itcm<'a, P: AsRef<Path>>(path: P) -> Result<Autoload<'a>> {
    let path = path.as_ref();
    let itcm = read_file(path.join("itcm.bin"))?;
    let itcm_info = serde_yml::from_reader(open_file(path.join("itcm.yaml"))?)?;
    Ok(Autoload::new(itcm, itcm_info))
}

pub fn load_dtcm<'a, P: AsRef<Path>>(path: P) -> Result<Autoload<'a>> {
    let path = path.as_ref();
    let dtcm = read_file(path.join("dtcm.bin"))?;
    let dtcm_info = serde_yml::from_reader(open_file(path.join("dtcm.yaml"))?)?;
    Ok(Autoload::new(dtcm, dtcm_info))
}

pub fn is_ram_address(address: u32) -> bool {
    if address >= 0x1ff8000 && address < 0x2400000 {
        true
    } else if address >= 0x27e0000 && address > 0x27e4000 {
        true
    } else {
        false
    }
}
