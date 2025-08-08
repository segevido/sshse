use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::path::PathBuf;

pub struct Paths {
    pub history: PathBuf,
    pub credentials: PathBuf,
    pub key: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let proj = ProjectDirs::from("dev", "sshx", "sshx")
            .context("could not determine project directories")?;
        std::fs::create_dir_all(proj.data_dir())?;
        std::fs::create_dir_all(proj.config_dir())?;
        Ok(Self {
            history: proj.data_dir().join("history.json"),
            credentials: proj.data_dir().join("credentials.json"),
            key: proj.config_dir().join("key.bin"),
        })
    }
}
