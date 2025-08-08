use anyhow::Result;
use dialoguer::FuzzySelect;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Serialize, Deserialize, Default)]
pub struct History {
    hosts: Vec<String>,
    #[serde(skip)]
    path: PathBuf,
}

impl History {
    pub fn new(path: PathBuf) -> Self {
        let hosts = if path.exists() {
            fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Self { hosts, path }
    }

    pub fn add(&mut self, host: &str) {
        self.hosts.retain(|h| h != host);
        self.hosts.insert(0, host.to_string());
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(&self.hosts)?;
        fs::write(&self.path, data)?;
        Ok(())
    }

    pub fn select(&self) -> Result<Option<String>> {
        if self.hosts.is_empty() {
            return Ok(None);
        }
        let idx = FuzzySelect::new()
            .with_prompt("Select host")
            .items(&self.hosts)
            .default(0)
            .interact_opt()?;
        Ok(idx.map(|i| self.hosts[i].clone()))
    }
}
