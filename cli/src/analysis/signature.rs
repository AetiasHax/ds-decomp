use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ds_decomp::{
    analysis::functions::Function,
    config::{module::Module, relocations::RelocationKind, symbol::SymbolMaps},
};
use serde::{Deserialize, Serialize};
use unarm::{ArmVersion, Endian, ParseFlags, ParseMode, Parser};

use crate::config::program::Program;

const SIGNATURES: &[(&str, &str)] = &[
    ("FS_LoadOverlay", include_str!("../../../assets/signatures/FS_LoadOverlay.yaml")),
    ("FS_UnloadOverlay", include_str!("../../../assets/signatures/FS_UnloadOverlay.yaml")),
];

#[derive(Serialize, Deserialize)]
pub struct Signatures {
    /// The function name these signatures are for.
    name: String,
    signatures: Vec<Signature>,
}

#[derive(Clone, Copy)]
pub struct SignatureIndex(usize);

#[derive(Serialize, Deserialize)]
pub struct Signature {
    #[serde(flatten)]
    mask: SignatureMask,
    /// External references within this function, if any, such as function calls or data accesses.
    relocations: Vec<SignatureRelocation>,
}

struct SignatureMask {
    bitmask: Vec<u8>,
    pattern: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignatureRelocation {
    /// Offset within the function code where this relocation occurs.
    offset: usize,
    /// Name of the object this relocation points to.
    name: String,
    kind: RelocationKind,
    #[serde(skip_serializing_if = "is_zero", default)]
    addend: i32,
}

fn is_zero(value: &i32) -> bool {
    *value == 0
}

pub enum ApplyResult {
    /// The signature was successfully applied.
    Applied,
    /// The signature was not applied because it did not match any function.
    NotFound,
    /// The signature was not applied because multiple functions matched.
    MultipleFound,
}

impl Signatures {
    pub fn from_function(function: &Function, module: &Module, symbol_maps: &SymbolMaps) -> Result<Self> {
        let function_code = function.code(module.code(), module.base_address());

        let parse_mode = if function.is_thumb() { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            parse_mode,
            function.start_address(),
            Endian::Little,
            ParseFlags { version: ArmVersion::V5Te, ual: false },
            function_code,
        );
        let mut bitmask = Vec::new();
        let mut pattern = Vec::new();
        let bl_offset_bits = if function.is_thumb() { 0x07ff07ff } else { 0x00ffffff };
        for (address, ins, parsed_ins) in parser {
            let mut ins_bitmask: u32 = 0xffffffff;

            if function.pool_constants().contains(&address) {
                // TODO: Only mask out pool constants which are pointers?
                parser.seek_forward(address + 4); // Skip pool constants
                bitmask.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                pattern.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                continue;
            }

            // Mask out function call addresses
            let mnemonic = ins.mnemonic();
            let is_bl_immediate = mnemonic == "bl" || mnemonic == "blx" && parsed_ins.branch_destination().is_some();
            if is_bl_immediate {
                ins_bitmask &= !bl_offset_bits;
            }

            let ins_size = if !function.is_thumb() || is_bl_immediate { 4 } else { 2 };
            let start = address - function.start_address();
            let end = start + ins_size as u32;
            let code = &function_code[start as usize..end as usize];

            let bitmask_bytes = &ins_bitmask.to_le_bytes()[..ins_size];
            let pattern_bytes = code.iter().zip(bitmask_bytes).map(|(&b, &m)| b & m);

            bitmask.extend_from_slice(bitmask_bytes);
            pattern.extend(pattern_bytes);
        }

        let relocations = module
            .relocations()
            .iter_range(function.start_address()..function.end_address())
            .filter_map(|(&address, relocation)| {
                let module_kind = relocation.destination_module()?;
                let dest_symbol_map = symbol_maps.get(module_kind)?;
                let (_, dest_symbol) = match dest_symbol_map.by_address(relocation.to_address()) {
                    Ok(symbol) => symbol?,
                    Err(e) => return Some(Err(e.into())),
                };
                Some(Ok(SignatureRelocation {
                    name: dest_symbol.name.clone(),
                    offset: (address - function.start_address()) as usize,
                    addend: relocation.addend_value(),
                    kind: relocation.kind(),
                }))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            name: function.name().to_string(),
            signatures: vec![Signature { mask: SignatureMask { bitmask, pattern }, relocations }],
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn list() -> Result<Vec<Self>> {
        SIGNATURES
            .iter()
            .map(|(name, yaml)| {
                serde_norway::from_str(yaml).map_err(|e| anyhow!("Failed to parse signature '{}': {}", name, e))
            })
            .collect::<Result<Vec<_>>>()
    }

    pub fn get(name: &str) -> Result<Self> {
        let signature_str = SIGNATURES
            .iter()
            .find(|(signature_name, _)| *signature_name == name)
            .ok_or_else(|| anyhow!("Signature '{}' not found", name))?;
        serde_norway::from_str(signature_str.1).map_err(|e| anyhow!("Failed to parse signature '{}': {}", name, e))
    }

    pub fn iter_names() -> impl Iterator<Item = &'static str> + 'static {
        SIGNATURES.iter().map(|(name, _)| *name)
    }

    pub fn apply(&self, program: &mut Program) -> Result<ApplyResult> {
        let matches = program
            .modules()
            .iter()
            .flat_map(|module| {
                self.find_matches(module)
                    .map(move |(function, signature)| (function.start_address(), module.kind(), signature))
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            Ok(ApplyResult::NotFound)
        } else if matches.len() > 1 {
            Ok(ApplyResult::MultipleFound)
        } else {
            let (function_address, module_kind, signature_index) = matches[0];
            let signature = &self.signatures[signature_index.0];

            {
                let symbol_maps = program.symbol_maps_mut();
                let symbol_map = symbol_maps.get_mut(module_kind);
                let changed = symbol_map.rename_by_address(function_address, &self.name)?;
                if changed {
                    log::info!("Renamed function at {:#010x} in {} to '{}'", function_address, module_kind, self.name);
                }
            }

            let module = program.by_module_kind_mut(module_kind).unwrap();
            let relocations = module.relocations_mut();

            let mut symbol_updates = vec![];
            for sig_relocation in &signature.relocations {
                let address = function_address + sig_relocation.offset as u32;
                let Some(relocation) = relocations.get_mut(address) else {
                    log::warn!(
                        "Relocation '{}' for signature '{}' not found at address {:#010x} in {}",
                        sig_relocation.name,
                        self.name,
                        address,
                        module_kind
                    );
                    continue;
                };
                let Some(destination_module) = relocation.destination_module() else {
                    log::warn!(
                        "Skipping ambiguous relocation '{}' for signature '{}' at address {:#010x} in {}",
                        sig_relocation.name,
                        self.name,
                        address,
                        module_kind
                    );
                    continue;
                };

                if relocation.kind() != sig_relocation.kind || relocation.addend_value() != sig_relocation.addend {
                    relocation.set_kind(sig_relocation.kind);
                    relocation.set_addend(sig_relocation.addend);
                    log::info!("Updated relocation '{}' at address {:#010x} in {}", sig_relocation.name, address, module_kind);
                }

                symbol_updates.push((destination_module, relocation.to_address(), &sig_relocation.name));
            }

            for (destination_module, to_address, name) in symbol_updates.into_iter() {
                let symbol_maps = program.symbol_maps_mut();
                let dest_symbol_map = symbol_maps.get_mut(destination_module);
                let changed = dest_symbol_map.rename_by_address(to_address, name)?;
                if changed {
                    log::info!("Renamed symbol at {:#010x} in {} to '{}'", to_address, destination_module, name);
                }
            }

            Ok(ApplyResult::Applied)
        }
    }

    pub fn find_matches<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = (&'a Function, SignatureIndex)> + 'a {
        module
            .sections()
            .functions()
            .filter_map(|function| self.match_signature(function, module).map(|signature| (function, signature)))
    }

    pub fn match_signature(&self, function: &Function, module: &Module) -> Option<SignatureIndex> {
        self.signatures
            .iter()
            .enumerate()
            .find_map(|(index, signature)| signature.matches(function, module).then_some(SignatureIndex(index)))
    }
}

impl Signature {
    pub fn matches(&self, function: &Function, module: &Module) -> bool {
        if function.size() as usize != self.mask.pattern.len() {
            return false;
        }
        function
            .code(module.code(), module.base_address())
            .iter()
            .zip(self.mask.bitmask.iter())
            .zip(self.mask.pattern.iter())
            .all(|((&code, &bitmask), &pattern)| (code & bitmask) == pattern)
    }
}

#[derive(Deserialize, Serialize)]
struct SignatureMaskData {
    bitmask: String,
    pattern: String,
}

impl Serialize for SignatureMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = SignatureMaskData { bitmask: STANDARD.encode(&self.bitmask), pattern: STANDARD.encode(&self.pattern) };
        data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignatureMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = SignatureMaskData::deserialize(deserializer)?;
        let bitmask = STANDARD.decode(data.bitmask).map_err(serde::de::Error::custom)?;
        let pattern = STANDARD.decode(data.pattern).map_err(serde::de::Error::custom)?;
        Ok(SignatureMask { bitmask, pattern })
    }
}
