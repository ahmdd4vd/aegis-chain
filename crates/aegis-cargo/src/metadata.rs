use std::path::PathBuf;

use aegis_core::AegisError;
use cargo_metadata::{Metadata, MetadataCommand};

#[derive(Debug, Clone)]
pub struct MetadataOptions {
    pub manifest_path: PathBuf,
    pub locked: bool,
    pub offline: bool,
}

impl Default for MetadataOptions {
    fn default() -> Self {
        Self {
            manifest_path: PathBuf::from("./Cargo.toml"),
            locked: true,
            offline: true,
        }
    }
}

impl MetadataOptions {
    pub fn new(manifest_path: impl Into<PathBuf>) -> Self {
        Self {
            manifest_path: manifest_path.into(),
            ..Self::default()
        }
    }
}

pub fn load_metadata(options: &MetadataOptions) -> Result<Metadata, AegisError> {
    let manifest_path = options.manifest_path.clone();

    if !manifest_path.is_file() {
        return Err(AegisError::Config(format!(
            "Cargo.toml not found at {}. Run from the workspace root or pass --manifest-path.",
            manifest_path.display()
        )));
    }

    let mut other_options = Vec::new();
    if options.locked {
        other_options.push("--locked".to_string());
    }
    if options.offline {
        other_options.push("--offline".to_string());
    }

    let mut command = MetadataCommand::new();
    command.manifest_path(&manifest_path);
    if !other_options.is_empty() {
        command.other_options(other_options);
    }

    let metadata = command.exec().map_err(|error| {
        AegisError::Runtime(format!(
            "`cargo metadata` failed for {}: {error}",
            manifest_path.display()
        ))
    })?;

    Ok(metadata)
}
