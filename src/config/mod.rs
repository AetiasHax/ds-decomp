pub mod config;
pub mod module;
pub mod symbol;

pub struct ParseContext {
    file_path: String,
    row: usize,
}
