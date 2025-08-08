mod config;
mod credentials;
mod history;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use dialoguer::Password;
use std::process::Command;

use config::Paths;
use credentials::CredentialsManager;
use history::History;

#[derive(Parser)]
#[command(name = "sshx", version, about = "Secure SSH helper")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Host to connect to
    host: Option<String>,
    /// Arguments passed to ssh
    #[arg(last = true)]
    ssh_args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Store credentials for a host
    Store {
        host: String,
        #[arg(short, long)]
        user: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::new()?;

    match cli.command {
        Some(Commands::Store { host, user }) => {
            let pwd = Password::new()
                .with_prompt("Password")
                .allow_empty_password(false)
                .interact()?;
            let mut creds = CredentialsManager::new(paths.credentials.clone(), paths.key.clone())?;
            creds.store(&host, &user, &pwd)?;
            creds.save()?;
            println!("Credentials saved for {host}");
        }
        None => {
            let mut history = History::new(paths.history.clone());
            let mut creds = CredentialsManager::new(paths.credentials.clone(), paths.key.clone())?;
            let host = match cli.host {
                Some(h) => h,
                None => history.select()?.context("no hosts in history")?,
            };
            history.add(&host);
            history.save()?;

            let host_for_ssh = if let Some((user, _pwd)) = creds.get(&host)? {
                format!("{user}@{host}")
            } else {
                host.clone()
            };

            let status = Command::new("ssh")
                .arg(host_for_ssh)
                .args(&cli.ssh_args)
                .status()
                .context("failed to execute ssh")?;
            if !status.success() {
                return Err(anyhow!("ssh exited with {}", status));
            }
        }
    }
    Ok(())
}
