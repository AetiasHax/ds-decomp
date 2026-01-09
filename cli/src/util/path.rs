use std::{
    backtrace::Backtrace,
    borrow::Cow,
    fmt::Display,
    io,
    path::{Path, PathBuf},
};

use path_slash::PathBufExt;
use pathdiff::diff_paths;
use snafu::Snafu;
use typed_path::{Utf8Path, Utf8UnixEncoding};

#[derive(Debug)]
pub struct StripPrefixErrorExt {
    path: PathBuf,
    prefix: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(display("failed to make '{path}' absoluate:\n{backtrace}"))]
pub struct AbsoluteError {
    path: String,
    error: io::Error,
    backtrace: Backtrace,
}

#[derive(Debug, Snafu)]
#[snafu(display("failed to diff path '{path}' with base '{base}':\n{backtrace}"))]
pub struct DiffPathsError {
    path: String,
    base: String,
    backtrace: Backtrace,
}

#[derive(Debug, Snafu)]
pub enum NormalizeDiffPathsError {
    #[snafu(transparent)]
    Absolute { source: AbsoluteError },
    #[snafu(transparent)]
    DiffPaths { source: DiffPathsError },
}

pub trait PathExt {
    fn strip_prefix_ext<P>(&self, base: P) -> Result<&Path, StripPrefixErrorExt>
    where
        P: AsRef<Path>;

    fn absolute(&self) -> Result<PathBuf, AbsoluteError>;

    fn diff_paths<P>(&self, base: P) -> Result<PathBuf, DiffPathsError>
    where
        P: AsRef<Path>;

    fn clean_diff_paths<P>(&self, path: P) -> Result<PathBuf, NormalizeDiffPathsError>
    where
        P: AsRef<Path>;

    fn clean(&self) -> PathBuf;
}

impl PathExt for Path {
    fn strip_prefix_ext<P>(&self, base: P) -> Result<&Path, StripPrefixErrorExt>
    where
        P: AsRef<Path>,
    {
        let base = base.as_ref();
        self.strip_prefix(base).map_err(|_| StripPrefixErrorExt { path: self.to_path_buf(), prefix: base.to_path_buf() })
    }

    fn absolute(&self) -> Result<PathBuf, AbsoluteError> {
        std::path::absolute(self).map_err(|error| AbsoluteSnafu { path: self.to_string_lossy(), error }.build())
    }

    fn diff_paths<P>(&self, base: P) -> Result<PathBuf, DiffPathsError>
    where
        P: AsRef<Path>,
    {
        let base = base.as_ref();
        match diff_paths(self, base) {
            Some(diff) => Ok(diff),
            None => DiffPathsSnafu { path: self.to_string_lossy(), base: base.to_string_lossy() }.fail(),
        }
    }

    fn clean_diff_paths<P>(&self, base: P) -> Result<PathBuf, NormalizeDiffPathsError>
    where
        P: AsRef<Path>,
    {
        let absolute = self.absolute()?;
        let diff = absolute.diff_paths(base)?;
        Ok(PathBuf::from(<Cow<'_, str> as AsRef<Utf8Path<Utf8UnixEncoding>>>::as_ref(&diff.to_slash_lossy())))
    }

    fn clean(&self) -> PathBuf {
        path_clean::clean(self)
    }
}

impl Display for StripPrefixErrorExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "prefix '{}' not found for '{}'", self.prefix.display(), self.path.display())
    }
}

impl std::error::Error for StripPrefixErrorExt {}
