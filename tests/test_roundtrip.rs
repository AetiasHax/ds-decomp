use core::str;
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Result;
use ds_decomp::{
    cmd::{CheckModules, Delink, Init, Lcf},
    config::config::Config,
    util::io::{open_file, read_to_string},
};
use ds_rom::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom},
};
use log::LevelFilter;
use zip::ZipArchive;

#[test]
fn test_roundtrip() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let cwd = std::env::current_dir()?;
    let assets_dir = cwd.join("tests/assets");
    let toolchain_dir = assets_dir.join("mwccarm");
    let arm7_bios = assets_dir.join("arm7_bios.bin");
    assert!(arm7_bios.exists());
    assert!(arm7_bios.is_file());

    let roms_dir = cwd.join("tests/roms/");
    let configs_dir = cwd.join("tests/configs/");

    if !toolchain_dir.exists() {
        download_toolchain(&assets_dir)?;
    }
    let linker_path = toolchain_dir.join("dsi/1.6sp2/mwldarm.exe");

    let key = BlowfishKey::from_arm7_bios_path(arm7_bios)?;

    for entry in roms_dir.read_dir()? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("nds")) {
            continue;
        }

        // Extract ROM
        let base_name = path.with_extension("").file_name().unwrap().to_str().unwrap().to_string();
        let project_path = roms_dir.join(&base_name);
        let extract_path = extract_rom(&path, &project_path, &key)?;
        let rom_config = extract_path.join("config.yaml");

        // Init dsd project
        let dsd_config_dir = dsd_init(&project_path, &rom_config)?;
        let dsd_config_yaml = dsd_config_dir.join("arm9/config.yaml");
        let dsd_config: Config = serde_yml::from_reader(open_file(&dsd_config_yaml)?)?;
        let target_config_dir = configs_dir.join(base_name);
        assert!(
            target_config_dir.exists(),
            "Init succeeded, copy the config directory to tests/configs/ to compare future runs"
        );

        assert!(directory_equals(&target_config_dir, &dsd_config_dir)?);

        // Delink modules
        let delink = Delink { config_path: dsd_config_yaml.clone() };
        delink.run()?;

        // Generate LCF
        let build_path = dsd_config_yaml.parent().unwrap().join(dsd_config.build_path);
        let lcf_file = build_path.join("linker_script.lcf");
        let objects_file = build_path.join("objects.txt");
        let lcf = Lcf { config_path: dsd_config_yaml.clone(), lcf_file: lcf_file.clone(), objects_file: objects_file.clone() };
        lcf.run()?;

        // Run linker
        let linker_out_file = build_path.join("arm9.o");
        let linker_output = Command::new(&linker_path)
            .args(["-proc", "arm946e"])
            .arg("-nostdlib")
            .arg("-interworking")
            .arg("-nodead")
            .args(["-m", "Entry"])
            .args(["-map", "closure,unused"])
            .arg(format!("@{}", objects_file.display()))
            .arg(lcf_file)
            .arg("-o")
            .arg(linker_out_file)
            .output()?;
        if !linker_output.status.success() {
            let stdout = str::from_utf8(&linker_output.stdout)?;
            log::error!("Linker failed, see stdout below");
            log::error!("{stdout}");
        }
        assert!(linker_output.status.success());

        // Check modules
        let check_modules = CheckModules { config_path: dsd_config_yaml.clone(), fail: true };
        check_modules.run()?;

        fs::remove_dir_all(project_path)?;
    }

    Ok(())
}

fn dsd_init(project_path: &Path, rom_config: &Path) -> Result<PathBuf> {
    let dsd_config_dir = project_path.join("config");
    let build_path = project_path.join("build");
    let init = Init { rom_config: rom_config.to_path_buf(), output_path: dsd_config_dir.clone(), dry: false, build_path };
    init.run()?;
    Ok(dsd_config_dir)
}

fn extract_rom(path: &Path, project_path: &Path, key: &BlowfishKey) -> Result<PathBuf> {
    let extract_path = project_path.join("extract");
    let raw_rom = raw::Rom::from_file(&path)?;
    let rom = Rom::extract(&raw_rom)?;
    rom.save(&extract_path, Some(key))?;
    Ok(extract_path)
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
    let base_lines = base_text.lines().collect::<Vec<_>>();

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

    // let mut num_wrong_lines = 0;
    // for i in 0..target_lines.len().min(base_lines.len()) {
    //     let target_line = target_lines[i];
    //     let base_line = base_lines[i];

    //     if target_line != base_line {
    //         matching = false;

    //         if num_wrong_lines >= 5 {
    //             log::error!("Max wrong lines reached, omitting the rest");
    //             break;
    //         }

    //         log::error!(
    //             "Line {} in base file '{}' does not match target file '{}':\n{}\n{}",
    //             i,
    //             target.display(),
    //             base.display(),
    //             base_line,
    //             target_line,
    //         );

    //         num_wrong_lines += 1;
    //     }
    // }

    Ok(matching)
}

fn download_toolchain(out_dir: &Path) -> Result<()> {
    log::info!("Downloading toolchain...");
    let bytes = reqwest::blocking::get("http://decomp.aetias.com/files/mwccarm.zip")?.bytes()?;
    let cursor = Cursor::new(bytes);
    let mut zip = ZipArchive::new(cursor)?;
    zip.extract(out_dir)?;

    Ok(())
}
