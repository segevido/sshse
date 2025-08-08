# sshx

`sshx` is a lightweight SSH manager written in Rust.
It wraps the system `ssh` client and adds features like host history and
encrypted credential storage.

## Usage

```sh
# connect to a host
sshx myserver

# connect and pass extra arguments to ssh
sshx myserver -p 2222

# store credentials securely
sshx store myserver --user alice

# run with no arguments to select from history
sshx
```

Configuration and data files are kept under `$XDG_DATA_HOME/sshx` (or the
platform equivalent).
