use std::{collections::HashMap, ffi::OsStr, fs, path::Path};

use anyhow::Result;
use ds_decomp::{cmd::Init, util::io::read_to_string};
use ds_rom::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom},
};
use log::LevelFilter;

#[test]
fn test_init() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let cwd = std::env::current_dir()?;
    let roms_dir = cwd.join("tests/roms/");
    let arm7_bios = roms_dir.join("arm7_bios.bin");
    assert!(arm7_bios.exists());
    assert!(arm7_bios.is_file());
    let configs_dir = cwd.join("tests/configs/");

    let key = BlowfishKey::from_arm7_bios_path(arm7_bios)?;

    for entry in roms_dir.read_dir()? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("nds")) {
            continue;
        }

        let base_name = path.with_extension("").file_name().unwrap().to_str().unwrap().to_string();
        let project_path = roms_dir.join(&base_name);
        let extract_path = project_path.join("extract");

        let raw_rom = raw::Rom::from_file(&path)?;
        let rom = Rom::extract(&raw_rom)?;
        rom.save(&extract_path, Some(&key))?;

        let rom_config = extract_path.join("config.yaml");

        let dsd_config_dir = project_path.join("config");
        let build_path = project_path.join("build");

        let init = Init { rom_config, output_path: dsd_config_dir.clone(), dry: false, build_path };
        init.run()?;

        let target_config_dir = configs_dir.join(base_name);

        if !directory_equals(&target_config_dir, &dsd_config_dir)? {
            break;
        }

        fs::remove_dir_all(project_path)?;
    }

    Ok(())
}

fn directory_equals(target: &Path, base: &Path) -> Result<bool> {
    log::debug!("Comparing target directory '{}' with base '{}'", target.display(), base.display());

    let mut matching = true;

    let target_entries = target
        .read_dir()?
        .map(|r| r.map(|e| (e.file_name().to_str().unwrap().to_string(), e.path())))
        .collect::<Result<HashMap<_, _>, _>>()?;
    let base_entries = base
        .read_dir()?
        .map(|r| r.map(|e| (e.file_name().to_str().unwrap().to_string(), e.path())))
        .collect::<Result<HashMap<_, _>, _>>()?;
    for (entry_name, target_path) in &target_entries {
        let Some(base_path) = base_entries.get(entry_name) else {
            matching = false;
            log::error!("Entry '{}' exists in target '{}' but not in base '{}'", entry_name, target.display(), base.display());
            continue;
        };

        if target_path.is_dir() && base_path.is_dir() {
            matching &= directory_equals(&target_path, &base_path)?;
        } else if target_path.is_file() && base_path.is_file() {
            matching &= file_equals(&target_path, &base_path)?;
        } else if target_path.is_file() && base_path.is_dir() {
            matching = false;
            log::error!(
                "Target entry '{}' is a file but base entry '{}' is a directory",
                target_path.display(),
                base_path.display()
            );
        } else if target_path.is_dir() && base_path.is_file() {
            matching = false;
            log::error!(
                "Target entry '{}' is a directory but base entry '{}' is a file",
                target_path.display(),
                base_path.display()
            );
        } else {
            matching = false;
            log::error!("Unknown entry types in target '{}' and/or base '{}'", target_path.display(), base_path.display());
        }
    }
    for (entry_name, _) in &base_entries {
        if target_entries.get(entry_name).is_none() {
            matching = false;
            log::error!("Entry '{}' exists in base '{}' but not in target '{}'", entry_name, base.display(), target.display())
        }
    }

    Ok(matching)
}

fn file_equals(target: &Path, base: &Path) -> Result<bool> {
    log::debug!("Comparing target file '{}' with base '{}'", target.display(), base.display());

    let mut matching = true;

    let target_text = read_to_string(target)?;
    let base_text = read_to_string(base)?;

    if target_text.len() != base_text.len() {
        log::error!(
            "Base file '{}' is {} bytes but target file '{}' is {} bytes long",
            base.display(),
            base_text.len(),
            target.display(),
            target_text.len()
        );
        matching = false;
    }

    let target_lines = target_text.lines().collect::<Vec<_>>();
    let base_lines = target_text.lines().collect::<Vec<_>>();

    if target_lines.len() != base_lines.len() {
        log::error!(
            "Base file '{}' is {} lines long but target file '{}' is {} lines long",
            base.display(),
            base_lines.len(),
            target.display(),
            target_lines.len()
        );
        matching = false;
    }

    let mut num_wrong_lines = 0;
    for i in 0..target_lines.len().min(base_lines.len()) {
        let target_line = target_lines[i];
        let base_line = base_lines[i];

        if target_line != base_line {
            matching = false;

            if num_wrong_lines >= 5 {
                log::error!("Max wrong lines reached, omitting the rest");
                break;
            }

            log::error!(
                "Line {} in base file '{}' does not match target file '{}':\n{}\n{}",
                i,
                target.display(),
                base.display(),
                base_line,
                target_line,
            );

            num_wrong_lines += 1;
        }
    }

    Ok(matching)
}
