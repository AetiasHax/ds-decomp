use std::{
    backtrace::Backtrace,
    fs::{self, File, ReadDir},
    io,
    path::Path,
};

use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum FileError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(display("the file '{path}' was not found:\n{backtrace}"))]
    FileNotFound { path: String, backtrace: Backtrace },
    #[snafu(display("parent directory does not exist for file '{path}':\n{backtrace}"))]
    FileParentNotFound { path: String, backtrace: Backtrace },
    #[snafu(display("the directory '{path}' was not found:\n{backtrace}"))]
    DirNotFound { path: String, backtrace: Backtrace },
    #[snafu(display("failed to read file '{path}', ran out of memory:\n{backtrace}"))]
    FileOutOfMemory { path: String, backtrace: Backtrace },
    #[snafu(display("failed to read file '{path}', ran out of memory:\n{backtrace}"))]
    DirOutOfMemory { path: String, backtrace: Backtrace },
    #[snafu(display("the file '{path}' already exists:\n{backtrace}"))]
    AlreadyExists { path: String, backtrace: Backtrace },
}

/// Wrapper for [`File::open`] with clearer errors.
pub fn open_file<P: AsRef<Path>>(path: P) -> Result<File, FileError> {
    let path = path.as_ref();
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            let path = path.to_string_lossy();
            match err.kind() {
                io::ErrorKind::NotFound => return FileNotFoundSnafu { path }.fail(),
                _ => Err(err)?,
            }
        }
    };
    Ok(file)
}

/// Wrapper for [`File::create`] with clearer errors.
pub fn create_file<P: AsRef<Path>>(path: P) -> Result<File, FileError> {
    let path = path.as_ref();
    let file = match File::create(path) {
        Ok(file) => file,
        Err(err) => {
            let path = path.to_string_lossy();
            match err.kind() {
                io::ErrorKind::AlreadyExists => return AlreadyExistsSnafu { path }.fail(),
                io::ErrorKind::NotFound => return FileParentNotFoundSnafu { path }.fail(),
                _ => Err(err)?,
            }
        }
    };
    Ok(file)
}

/// Wrapper for [`fs::read`] with clearer errors.
pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, FileError> {
    let path = path.as_ref();
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let path = path.to_string_lossy();
            match err.kind() {
                io::ErrorKind::NotFound => return FileNotFoundSnafu { path }.fail(),
                io::ErrorKind::OutOfMemory => return FileOutOfMemorySnafu { path }.fail(),
                _ => todo!(),
            }
        }
    };
    Ok(bytes)
}

/// Wrapper for [`fs::write`] with clearer errors.
pub fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<(), FileError> {
    let path = path.as_ref();
    let contents = contents.as_ref();
    let bytes = match fs::write(path, contents) {
        Ok(bytes) => bytes,
        Err(err) => {
            let path = path.to_string_lossy();
            match err.kind() {
                io::ErrorKind::AlreadyExists => return AlreadyExistsSnafu { path }.fail(),
                _ => Err(err)?,
            }
        }
    };
    Ok(bytes)
}

/// Wrapper for [`fs::read_to_string`] with clearer errors.
pub fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String, FileError> {
    let path = path.as_ref();
    let string = match fs::read_to_string(path) {
        Ok(string) => string,
        Err(err) => {
            let path = path.to_string_lossy();
            match err.kind() {
                io::ErrorKind::NotFound => return FileNotFoundSnafu { path }.fail(),
                io::ErrorKind::OutOfMemory => return FileOutOfMemorySnafu { path }.fail(),
                _ => Err(err)?,
            }
        }
    };
    Ok(string)
}

/// Wrapper for [`fs::read_dir`] with clearer errors.
pub fn read_dir<P: AsRef<Path>>(path: P) -> Result<ReadDir, FileError> {
    let path = path.as_ref();
    let dir = match fs::read_dir(path) {
        Ok(dir) => dir,
        Err(err) => {
            let path = path.to_string_lossy();
            match err.kind() {
                io::ErrorKind::NotFound => return DirNotFoundSnafu { path }.fail(),
                io::ErrorKind::OutOfMemory => return DirOutOfMemorySnafu { path }.fail(),
                _ => Err(err)?,
            }
        }
    };
    Ok(dir)
}

/// Wrapper for [`fs::create_dir_all`] with clearer errors.
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<(), FileError> {
    let path = path.as_ref();
    if let Err(err) = fs::create_dir_all(path) {
        let path = path.to_string_lossy();
        match err.kind() {
            io::ErrorKind::NotFound => return DirNotFoundSnafu { path }.fail(),
            _ => Err(err)?,
        }
    }
    Ok(())
}
