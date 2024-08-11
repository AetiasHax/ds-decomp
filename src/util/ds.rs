use std::path::Path;

use anyhow::Result;
use ds_rom::rom::{self, Arm9, Arm9BuildConfig, Autoload, Header};

use super::io::{open_file, read_file};

pub fn load_arm9<P: AsRef<Path>>(path: P, header: &Header) -> Result<Arm9> {
    let path = path.as_ref();

    let arm9_bin_file = path.join("arm9.bin");

    let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(open_file(path.join("arm9.yaml"))?)?;
    let arm9 = read_file(&arm9_bin_file)?;

    let itcm = read_file(path.join("itcm.bin"))?;
    let itcm_info = serde_yml::from_reader(open_file(path.join("itcm.yaml"))?)?;
    let itcm = Autoload::new(itcm, itcm_info);

    let dtcm = read_file(path.join("dtcm.bin"))?;
    let dtcm_info = serde_yml::from_reader(open_file(path.join("dtcm.yaml"))?)?;
    let dtcm = Autoload::new(dtcm, dtcm_info);

    let arm9 = rom::Arm9::with_two_tcms(arm9, itcm, dtcm, header.version(), arm9_build_config.offsets)?;
    Ok(arm9)
}
