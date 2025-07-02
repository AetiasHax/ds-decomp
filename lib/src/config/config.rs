use std::{
    backtrace::Backtrace,
    path::{Path, PathBuf},
};

use ds_rom::rom::raw::AutoloadKind;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{
    config::{
        delinks::{Delinks, DelinksParseError},
        module::{Module, ModuleError, ModuleKind, ModuleOptions},
        relocations::{Relocations, RelocationsParseError},
        symbol::SymbolMaps,
    },
    util::io::{self, open_file, FileError},
};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub rom_config: PathBuf,
    pub build_path: PathBuf,
    pub delinks_path: PathBuf,
    pub main_module: ConfigModule,
    pub autoloads: Vec<ConfigAutoload>,
    pub overlays: Vec<ConfigOverlay>,
}

#[derive(Debug, Snafu)]
pub enum ConfigParseError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(display("Failed to parse dsd config file '{}': {error}\n{backtrace}", path.display()))]
    SerdeYml { path: PathBuf, error: serde_yml::Error, backtrace: Backtrace },
}

#[derive(Debug, Snafu)]
pub enum LoadModuleError {
    #[snafu(display("Failed to load module config for kind {module_kind}: \n{backtrace}"))]
    ModuleConfigNotFound { module_kind: ModuleKind, backtrace: Backtrace },
    #[snafu(transparent)]
    RelocationsParse { source: RelocationsParseError },
    #[snafu(transparent)]
    DelinksParse { source: DelinksParseError },
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(transparent)]
    Module { source: ModuleError },
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Config, ConfigParseError> {
        let file = open_file(path)?;
        serde_yml::from_reader(file).map_err(|error| SerdeYmlSnafu { path, error }.build())
    }

    pub fn get_module_config_by_kind(&self, module_kind: ModuleKind) -> Option<&ConfigModule> {
        match module_kind {
            ModuleKind::Arm9 => Some(&self.main_module),
            ModuleKind::Autoload(autoload_kind) => {
                self.autoloads.iter().find(|autoload| autoload.kind == autoload_kind).map(|autoload| &autoload.module)
            }
            ModuleKind::Overlay(id) => self.overlays.iter().find(|overlay| overlay.id == id).map(|overlay| &overlay.module),
        }
    }

    pub fn load_module<P: AsRef<Path>>(
        &self,
        config_path: P,
        symbol_maps: &mut SymbolMaps,
        module_kind: ModuleKind,
    ) -> Result<Module, LoadModuleError> {
        let config_path = config_path.as_ref();
        let symbol_map = symbol_maps.get_mut(module_kind);
        let module_config =
            self.get_module_config_by_kind(module_kind).ok_or_else(|| ModuleConfigNotFoundSnafu { module_kind }.build())?;
        let relocations = Relocations::from_file(config_path.join(&module_config.relocations))?;
        let delinks = Delinks::from_file(config_path.join(&module_config.delinks), module_kind)?;
        let code = if delinks.sections.text_size() == 0 {
            vec![]
        } else {
            io::read_file(config_path.join(&module_config.object))?
        };

        let module = Module::new(
            symbol_map,
            ModuleOptions {
                kind: module_kind,
                name: module_config.name.clone(),
                relocations,
                sections: delinks.sections,
                code: &code,
                signed: false,
            },
        )?;

        Ok(module)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConfigModule {
    /// Name of module
    pub name: String,
    /// Binary file to build
    pub object: PathBuf,
    /// 64-bit fxhash of the binary file
    pub hash: String,
    /// Path to delinks file
    pub delinks: PathBuf,
    /// Path to symbols file
    pub symbols: PathBuf,
    /// Path to relocs file
    pub relocations: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigOverlay {
    pub id: u16,
    #[serde(default = "default_overlay_signed", skip_serializing_if = "skip_overlay_signed")]
    pub signed: bool,
    #[serde(flatten)]
    pub module: ConfigModule,
}

fn default_overlay_signed() -> bool {
    false
}

fn skip_overlay_signed(signed: &bool) -> bool {
    *signed == default_overlay_signed()
}

#[derive(Serialize, Deserialize)]
pub struct ConfigAutoload {
    pub kind: AutoloadKind,
    #[serde(flatten)]
    pub module: ConfigModule,
}
