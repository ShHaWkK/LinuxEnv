# LinuxEnv

This project provides `script2.sh`, a Bash utility to manage a secured
workspace. It creates an encrypted LUKS container and offers helpers for
GPG and SSH configuration.

## Features

* **Encrypted environment** – creates a 5 GiB container formatted in ext4
  and mounts it on demand.
* **GPG management** – generate keys inside the vault, export your
  existing keys to the vault or import them back into your keyring.
* **SSH vault** – build a template configuration usable with `ssh -F` and
  import any host defined in `~/.ssh/config`. The corresponding keys are
  copied into the vault and the alias `evsh` (via `~/.aliases_env`) runs
  `ssh` with that file.
* **Backups** – create and restore archives of the SSH wallet.

## Usage

Run the script as root and use either the menu interface or individual
commands:

```bash
sudo ./script2.sh --menu            # interactive mode
sudo ./script2.sh install_env       # create container
sudo ./script2.sh open_env          # open and mount
sudo ./script2.sh close_env         # unmount and close
sudo ./script2.sh gpg_setup         # generate GPG keys
sudo ./script2.sh gpg_export        # export keys to the vault
sudo ./script2.sh gpg_import        # import keys from the vault
sudo ./script2.sh ssh_create_template  # create the initial SSH template
sudo ./script2.sh ssh_import_host      # add a host from ~/.ssh/config
sudo ./script2.sh ssh_setup_alias      # create alias evsh
```

Source `~/.aliases_env` to get the `evsh` command:

```bash
source ~/.aliases_env
```

The environment can also be automatically opened at login using the
`auto_open_toggle` action.
