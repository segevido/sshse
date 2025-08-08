use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Serialize, Deserialize)]
struct StoredCredential {
    username: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Default)]
struct CredentialsFile {
    hosts: HashMap<String, StoredCredential>,
}

pub struct CredentialsManager {
    path: PathBuf,
    key_path: PathBuf,
    key: LessSafeKey,
    data: CredentialsFile,
}

impl CredentialsManager {
    pub fn new(path: PathBuf, key_path: PathBuf) -> Result<Self> {
        let mut key_bytes = vec![0u8; 32];
        if key_path.exists() {
            key_bytes = fs::read(&key_path).context("failed to read key")?;
        } else {
            let rng = SystemRandom::new();
            rng.fill(&mut key_bytes)
                .map_err(|_| anyhow!("failed to generate key"))?;
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&key_path, &key_bytes)?;
        }
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| anyhow!("invalid key length"))?;
        let key = LessSafeKey::new(unbound);

        let data = if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s).unwrap_or_default()
        } else {
            CredentialsFile::default()
        };
        Ok(Self {
            path,
            key_path,
            key,
            data,
        })
    }

    pub fn store(&mut self, host: &str, user: &str, password: &str) -> Result<()> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow!("failed to generate nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = password.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("encryption failure"))?;

        let entry = StoredCredential {
            username: user.to_string(),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            ciphertext: general_purpose::STANDARD.encode(&in_out),
        };
        self.data.hosts.insert(host.to_string(), entry);
        Ok(())
    }

    pub fn get(&self, host: &str) -> Result<Option<(String, String)>> {
        let entry = match self.data.hosts.get(host) {
            Some(e) => e,
            None => return Ok(None),
        };
        let nonce_vec = general_purpose::STANDARD
            .decode(&entry.nonce)
            .context("invalid nonce")?;
        let nonce_arr: [u8; 12] = nonce_vec
            .try_into()
            .map_err(|_| anyhow!("invalid nonce length"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let mut cipher = general_purpose::STANDARD
            .decode(&entry.ciphertext)
            .context("invalid ciphertext")?;
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut cipher)
            .map_err(|_| anyhow!("decryption failure"))?;
        let password = String::from_utf8(plain.to_vec())?;
        Ok(Some((entry.username.clone(), password)))
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = serde_json::to_string_pretty(&self.data)?;
        fs::write(&self.path, s)?;
        Ok(())
    }
}
