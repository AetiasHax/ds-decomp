use core::str;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Result;
use ds_decomp::config::config::Config;
use ds_decomp_cli::{
    analysis::data::AnalyzeExternalReferencesError,
    cmd::{CheckModules, CheckSymbols, ConfigRom, Delink, Disassemble, Init, Lcf},
    util::io::read_to_string,
};
use ds_rom::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom},
};
use log::LevelFilter;
use zip::ZipArchive;

#[test]
fn test_roundtrip() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Debug).init();

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
        let dsd_config_dir = dsd_init(&project_path, &rom_config, false).or_else(|e| match e
            .downcast_ref::<AnalyzeExternalReferencesError>()
        {
            Some(AnalyzeExternalReferencesError::LocalFunctionNotFound { .. }) => {
                log::info!("dsd init failed, trying again with unknown function calls");
                dsd_init(&project_path, &rom_config, true)
            }
            _ => Err(e),
        })?;
        let dsd_config_yaml = dsd_config_dir.join("arm9/config.yaml");
        let dsd_config = Config::from_file(&dsd_config_yaml)?;
        let target_config_dir = configs_dir.join(base_name);
        assert!(
            target_config_dir.exists(),
            "Init succeeded, copy the config directory to tests/configs/ to compare future runs"
        );

        assert!(directory_equals(&target_config_dir, &dsd_config_dir)?);

        // Disassemble
        let disassemble = Disassemble { config_path: dsd_config_yaml.clone(), asm_path: project_path.join("asm"), ual: false };
        disassemble.run()?;

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
        let mut command;
        #[cfg(target_os = "windows")]
        {
            command = Command::new(&linker_path);
        }
        #[cfg(not(target_os = "windows"))]
        {
            command = Command::new("wine");
            command.arg(&linker_path);
        }
        let linker_output = command
            .args(["-proc", "arm946e"])
            .arg("-nostdlib")
            .arg("-interworking")
            .arg("-nodead")
            .args(["-m", "Entry"])
            .args(["-map", "closure,unused"])
            .arg(format!("@{}", objects_file.display()))
            .arg(lcf_file)
            .arg("-o")
            .arg(&linker_out_file)
            .output()?;
        if !linker_output.status.success() {
            let stdout = str::from_utf8(&linker_output.stdout)?;
            log::error!("Linker failed, see stdout below");
            log::error!("{stdout}");
        }
        assert!(linker_output.status.success());

        // Check symbols
        let check_symbols =
            CheckSymbols { config_path: dsd_config_yaml.clone(), fail: true, elf_path: linker_out_file.clone(), max_lines: 3 };
        check_symbols.run()?;

        // Check modules
        let check_modules = CheckModules { config_path: dsd_config_yaml.clone(), fail: true };
        check_modules.run()?;

        // Configure ds-rom
        let config_rom = ConfigRom { elf: linker_out_file.clone(), config: dsd_config_yaml.clone() };
        config_rom.run()?;

        fs::remove_dir_all(project_path)?;
    }

    Ok(())
}

fn dsd_init(project_path: &Path, rom_config: &Path, allow_unknown_function_calls: bool) -> Result<PathBuf> {
    let dsd_config_dir = project_path.join("config");
    let build_path = project_path.join("build");
    let init = Init {
        rom_config: rom_config.to_path_buf(),
        output_path: dsd_config_dir.clone(),
        dry: false,
        build_path,
        skip_reloc_analysis: false,
        allow_unknown_function_calls,
        provide_reloc_source: false,
    };
    init.run()?;
    Ok(dsd_config_dir)
}

fn extract_rom(path: &Path, project_path: &Path, key: &BlowfishKey) -> Result<PathBuf> {
    let extract_path = project_path.join("extract");
    let raw_rom = raw::Rom::from_file(path)?;
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
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let base_entries = base
        .read_dir()?
        .map(|r| r.map(|e| (e.file_name().to_str().unwrap().to_string(), e.path())))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for (entry_name, target_path) in &target_entries {
        let Some(base_path) = base_entries.get(entry_name) else {
            matching = false;
            log::error!("Entry '{}' exists in target '{}' but not in base '{}'", entry_name, target.display(), base.display());
            continue;
        };

        if target_path.is_dir() && base_path.is_dir() {
            matching &= directory_equals(target_path, base_path)?;
        } else if target_path.is_file() && base_path.is_file() {
            matching &= file_equals(target_path, base_path)?;
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
    for entry_name in base_entries.keys() {
        if !target_entries.contains_key(entry_name) {
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

    if target_text != base_text {
        log::error!("Base file '{}' does not match target file '{}'", base.display(), target.display(),);
        matching = false;
    }

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
