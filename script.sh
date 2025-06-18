#!/bin/bash
# Author  : ShHawk alias Alexandre Uzan
# Sujet   : Environnement Sécurisé complet (LUKS, GPG, SSH)

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

(( EUID == 0 )) || { echo "[Erreur] exécuter en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid gpg; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[Erreur] $cmd manquant"; exit 1; }
done

# Variables
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPING="env_sec"
MOUNT_POINT="$HOME/env_mount"
ALIAS_LINK="$HOME/.aliases_env"

# Prépare les dossiers
mkdir -p "${CONTAINER%/*}" "$MOUNT_POINT"

# Affichages
show_lsblk() { echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; echo; }
show_df()    { echo; df -Th | grep -E "$MAPPING|Filesystem"; echo; }
show_blkid() { echo; blkid /dev/mapper/"$MAPPING" 2>/dev/null || echo "(pas de mapping ouvert)"; echo; }

# Utilitaires
read_size_and_pass() {
  read -p "Taille du conteneur (ex: 5G, 500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS; echo
  read -s -p "Confirmer le mot de passe : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { echo "[Erreur] mots de passe différents"; exit 1; }
}

attach_loop() {
  LOOPDEV=$(losetup --find --show "$CONTAINER")
  echo "$LOOPDEV" >"$LOOP_FILE"
}

detach_loop() {
  [[ -f "$LOOP_FILE" ]] && {
    losetup -d "$(cat "$LOOP_FILE")"
    rm -f "$LOOP_FILE"
  }
}

unlock_volume() {
  printf '%s' "$PASS" | cryptsetup open --type luks1 --key-file=- "$1" "$MAPPING"
}

lock_volume() {
  cryptsetup close "$MAPPING"
}

format_volume() {
  mkfs.ext4 /dev/mapper/"$MAPPING"
}

mount_volume() {
  mount /dev/mapper/"$MAPPING" "$MOUNT_POINT"
}

umount_volume() {
  umount "$MOUNT_POINT" 2>/dev/null || :
}

set_permissions() {
  chmod 600 "$CONTAINER"
  chmod -R go-rwx "$MOUNT_POINT"
}

# Commandes principales
install() {
  echo ">>> INSTALL <<<"
  show_lsblk
  read_size_and_pass

  [[ -f "$CONTAINER" ]] && { echo "[Erreur] conteneur existe"; exit 1; }
  cryptsetup status "$MAPPING" &>/dev/null && { echo "[Erreur] mapping existe"; exit 1; }

  if ! fallocate -l "$SIZE" "$CONTAINER" 2>/dev/null; then
    COUNT=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && COUNT=$((COUNT*1024))
    dd if=/dev/zero of="$CONTAINER" bs=1M count="$COUNT" status=progress
  fi
  attach_loop; show_lsblk
  printf '%s' "$PASS" | cryptsetup luksFormat --type luks1 --batch-mode "$LOOPDEV" --key-file=-
  unlock_volume "$LOOPDEV"
  format_volume
  mount_volume
  set_permissions
  show_lsblk; show_df; show_blkid
  echo "[OK] Environnement installé et monté sur $MOUNT_POINT"
}

open() {
  echo ">>> OPEN <<<"
  show_lsblk
  [[ ! -f "$CONTAINER" ]] && { echo "[Erreur] pas de conteneur"; exit 1; }
  [[ -f "$LOOP_FILE" ]] || attach_loop

  if [[ ! -e /dev/mapper/"$MAPPING" ]]; then
    read -s -p "Mot de passe LUKS : " PASS; echo
    unlock_volume "$(cat "$LOOP_FILE")"
    echo "[OK] Volume déverrouillé"
  fi
  mountpoint -q "$MOUNT_POINT" || mount_volume
  set_permissions
  show_df
}

close() {
  echo ">>> CLOSE <<<"
  umount_volume && echo "[OK] Démonté"
  [[ -e /dev/mapper/"$MAPPING" ]] && (lock_volume && echo "[OK] Verrouillé")
  detach_loop && echo "[OK] Loop détaché"
  show_lsblk
}

delete() {
  echo ">>> DELETE <<<"
  close || :
  rm -f "$CONTAINER" && echo "[OK] Conteneur supprimé"
  rmdir "$MOUNT_POINT" 2>/dev/null || :
}

# GPG
gpg_setup() {
  echo ">>> GPG SETUP <<<"
  read -p "Nom : " NAME
  read -p "Email : " EMAIL
  read -p "Commentaire : " COMMENT

  cat >gpg-batch <<EOF
%no-protection
Key-Type: default
Subkey-Type: default
Name-Real: $NAME
Name-Comment: $COMMENT
Name-Email: $EMAIL
Expire-Date: 0
%commit
EOF

  gpg --batch --generate-key gpg-batch
  rm -f gpg-batch
  KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}' | head -n1)
  gpg --export --armor "$KEYID" > "$MOUNT_POINT/public_$KEYID.gpg"
  gpg --export-secret-keys --armor "$KEYID" > "$MOUNT_POINT/private_$KEYID.gpg"
  chmod 600 "$MOUNT_POINT/private_$KEYID.gpg"
  echo "[OK] Clés exportées dans le coffre"
}

gpg_import() {
  echo ">>> GPG IMPORT <<<"
  for f in "$MOUNT_POINT"/*.gpg; do
    gpg --import "$f" && echo "[OK] Importé $f"
  done
}

# SSH
ssh_setup() {
  echo ">>> SSH SETUP <<<"
  TEMPLATE="$MOUNT_POINT/ssh_config"
  ALIAS_FILE="$MOUNT_POINT/.aliases"
  echo "Host *" > "$TEMPLATE"
  echo "  User $(whoami)" >> "$TEMPLATE"
  echo "  IdentityFile ~/.ssh/id_rsa" >> "$TEMPLATE"

  echo "alias evsh='ssh -F $TEMPLATE'" > "$ALIAS_FILE"
  ln -sf "$ALIAS_FILE" "$ALIAS_LINK"

  if [[ -f "$HOME/.ssh/config" ]]; then
    grep ^Host "$HOME/.ssh/config" | awk '{print " -", $2}'
    read -p "Host à importer : " CHOSEN
    awk "/^Host $CHOSEN\$/,/^Host /" "$HOME/.ssh/config" > "$TEMPLATE"

    if grep -q "IdentityFile" "$TEMPLATE"; then
      OLD_KEY=$(grep IdentityFile "$TEMPLATE" | awk '{print $2}')
      NEW_KEY="$MOUNT_POINT/$(basename "$OLD_KEY")"
      sed -i "s|$OLD_KEY|$NEW_KEY|" "$TEMPLATE"
      cp "$OLD_KEY" "$NEW_KEY"
      chmod 600 "$NEW_KEY"
    fi
    echo "[OK] SSH $CHOSEN importé dans le coffre"
  fi
}

# Help
usage() {
  echo "Usage: $0 {install|open|close|delete|gpg-setup|gpg-import|ssh-setup}"
  exit 1
}

# Dispatcher
[[ $# -ne 1 ]] && usage
case "$1" in
  install)     install ;;
  open)        open ;;
  close)       close ;;
  delete)      delete ;;
  gpg-setup)   gpg_setup ;;
  gpg-import)  gpg_import ;;
  ssh-setup)   ssh_setup ;;
  *)           usage ;;
esac
