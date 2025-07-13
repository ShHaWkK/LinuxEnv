#!/usr/bin/env bash
set -euo pipefail

# Secure environment paths
USER_NAME=${SUDO_USER:-$(id -un)}
USER_HOME=$(eval echo "~$USER_NAME")
CONTAINER="$USER_HOME/secure_env.img"
MAPPER="secure_env"
MOUNT="$USER_HOME/env_mount"
COFFRE="$MOUNT"
BACKUP_DIR="$USER_HOME/env_backups"

# Ensure directories exist
mkdir -p "$BACKUP_DIR"

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This command must be run as root" >&2
    exit 1
  fi
}

ensure_mounted() {
  if ! mountpoint -q "$MOUNT"; then
    echo "Vault not mounted. Run '$0 open' first." >&2
    exit 1
  fi
}

install() {
  require_root
  if [[ -f "$CONTAINER" ]]; then
    echo "Container already exists at $CONTAINER" >&2
    exit 1
  fi
  echo "Creating 5GiB container..."
  fallocate -l 5G "$CONTAINER"
  chmod 600 "$CONTAINER"
  chown "$USER_NAME:$USER_NAME" "$CONTAINER"

  echo "Initializing LUKS..."
  cryptsetup luksFormat "$CONTAINER"
  echo "Opening container..."
  cryptsetup open "$CONTAINER" "$MAPPER"
  mkfs.ext4 "/dev/mapper/$MAPPER"
  mkdir -p "$MOUNT"
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chown "$USER_NAME:$USER_NAME" "$MOUNT"
  chmod go-rwx "$MOUNT"
  mkdir -p "$MOUNT/gpg" "$MOUNT/ssh"
  echo "Environment installed and mounted at $MOUNT"
}

open() {
  require_root
  cryptsetup open "$CONTAINER" "$MAPPER"
  mkdir -p "$MOUNT"
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chown "$USER_NAME:$USER_NAME" "$MOUNT"
  chmod go-rwx "$MOUNT"
  echo "Vault mounted at $MOUNT"
}

close() {
  require_root
  umount "$MOUNT" 2>/dev/null || true
  cryptsetup close "$MAPPER" 2>/dev/null || true
  echo "Vault closed"
}

gpg_setup() {
  ensure_mounted
  read -p "Name: " NAME
  read -p "Email: " EMAIL
  KEYFILE=$(mktemp)
  cat > "$KEYFILE" <<EOF_GPG
%no-protection
Key-Type: default
Subkey-Type: default
Name-Real: $NAME
Name-Email: $EMAIL
Expire-Date: 0
%commit
EOF_GPG
  gpg --batch --generate-key "$KEYFILE"
  rm -f "$KEYFILE"
  KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5; exit}')
  mkdir -p "$COFFRE/gpg"
  gpg --export --armor "$KEYID" > "$COFFRE/gpg/public_${KEYID}.gpg"
  read -p "Export private key? [y/N]: " yn
  if [[ $yn =~ ^[Yy]$ ]]; then
    gpg --export-secret-keys --armor "$KEYID" > "$COFFRE/gpg/private_${KEYID}.gpg"
    chmod 600 "$COFFRE/gpg/private_${KEYID}.gpg"
  fi
  echo "GPG key $KEYID exported to $COFFRE/gpg/"
}

gpg_import() {
  ensure_mounted
  shopt -s nullglob
  for f in "$COFFRE"/gpg/*.gpg; do
    gpg --import "$f"
  done
  shopt -u nullglob
  echo "GPG keys imported"
}

list_hosts() {
  grep '^Host ' "$HOME/.ssh/config" | awk '{print $2}'
}

ssh_template() {
  ensure_mounted
  [[ -f "$HOME/.ssh/config" ]] || { echo "No ~/.ssh/config" >&2; return; }
  mapfile -t hosts < <(list_hosts)
  [[ ${#hosts[@]} -gt 0 ]] || { echo "No hosts found" >&2; return; }
  echo "Choose host:" >&2
  select host in "${hosts[@]}"; do
    [[ -n "$host" ]] && break
  done
  [[ -n "$host" ]] || return
  local conf="$COFFRE/ssh/sshconf_${host}"
  awk "/^Host $host\$/,/^Host /" "$HOME/.ssh/config" > "$conf"
  local idf
  idf=$(awk "/^Host $host\$/,/^Host /" "$HOME/.ssh/config" | awk '/IdentityFile/ {print $2; exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$COFFRE/ssh/" && chmod 600 "$COFFRE/ssh/$(basename "$idf")"
    [[ -f "${idf}.pub" ]] && { cp "${idf}.pub" "$COFFRE/ssh/" && chmod 644 "$COFFRE/ssh/$(basename "$idf").pub"; }
    sed -i "s|$idf|$COFFRE/ssh/$(basename "$idf")|" "$conf"
  fi
  chmod -R go-rwx "$COFFRE/ssh"
  chown -R "$USER_NAME:$USER_NAME" "$COFFRE/ssh"
  echo "Template created: $conf"
}

ssh_alias() {
  cat > "$HOME/.env_aliases" <<'EOF_ALIAS'
function evsh() {
  ssh -F ~/env_mount/ssh/sshconf_$1 "$1"
}
EOF_ALIAS
  ln -sf "$HOME/.env_aliases" "$HOME/.aliases_env"
  if [[ -f "$HOME/.bash_aliases" ]]; then
    grep -q ".aliases_env" "$HOME/.bash_aliases" || echo "source ~/.aliases_env" >> "$HOME/.bash_aliases"
  fi
  echo "Alias created. Source ~/.aliases_env or ~/.bash_aliases"
}

ssh_import() {
  ssh_template "$@"
}

ssh_start() {
  ensure_mounted
  shopt -s nullglob
  mapfile -t confs < <(basename -a "$COFFRE"/ssh/sshconf_*)
  shopt -u nullglob
  [[ ${#confs[@]} -gt 0 ]] || { echo "No ssh configurations" >&2; return; }
  local hosts=()
  for c in "${confs[@]}"; do hosts+=("${c#sshconf_}"); done
  echo "Choose host:" >&2
  select h in "${hosts[@]}"; do
    [[ -n "$h" ]] && break
  done
  [[ -n "$h" ]] || return
  ssh -F "$COFFRE/ssh/sshconf_$h" "$h"
}

ssh_backup() {
  ensure_mounted
  mkdir -p "$BACKUP_DIR"
  local ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$BACKUP_DIR/ssh_wallet_${ts}.tar.gz" -C "$COFFRE/ssh" .
  echo "Backup created: $BACKUP_DIR/ssh_wallet_${ts}.tar.gz"
}

ssh_restore() {
  ensure_mounted
  mapfile -t files < <(ls "$BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  [[ ${#files[@]} -gt 0 ]] || { echo "No backup found" >&2; return; }
  echo "Choose backup:" >&2
  select f in "${files[@]}"; do
    [[ -n "$f" ]] && break
  done
  [[ -n "$f" ]] || return
  tar xzf "$f" -C "$COFFRE/ssh"
  echo "Backup restored from $f"
}

case "${1:-}" in
  install) install ;;
  open) open ;;
  close) close ;;
  gpg-setup) gpg_setup ;;
  gpg-import) gpg_import ;;
  ssh-template) ssh_template ;;
  ssh-alias) ssh_alias ;;
  ssh-import) ssh_import ;;
  ssh-start) ssh_start ;;
  ssh-backup) ssh_backup ;;
  ssh-restore) ssh_restore ;;
  *)
    echo "Usage: $0 {install|open|close|gpg-setup|gpg-import|ssh-template|ssh-alias|ssh-import|ssh-start|ssh-backup|ssh-restore}" >&2
    exit 1
    ;;
esac
