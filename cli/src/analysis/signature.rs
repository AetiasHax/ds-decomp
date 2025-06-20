use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ds_decomp::{
    analysis::functions::Function,
    config::{
        module::Module,
        relocations::{RelocationKind, RelocationModule},
        symbol::SymbolMaps,
    },
};
use serde::{Deserialize, Serialize};
use unarm::{ArmVersion, Endian, ParseFlags, ParseMode, Parser};

#[derive(Serialize, Deserialize)]
pub struct Signature {
    #[serde(flatten)]
    mask: SignatureMask,
    /// The function name this signature is for.
    name: String,
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
    module: RelocationModule,
    kind: RelocationKind,
    #[serde(skip_serializing_if = "is_zero")]
    addend: i32,
}

fn is_zero(value: &i32) -> bool {
    *value == 0
}

impl Signature {
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
                    module: module_kind.into(),
                }))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { mask: SignatureMask { bitmask, pattern }, name: function.name().to_string(), relocations })
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
