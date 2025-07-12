#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Coffre Sécurisé complet (LUKS, ext4, GPG, SSH) – menu + résumé

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# Couleurs
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }
log()     { echo "$*" >>"$LOG"; }

# Dépendances et root
(( EUID==0 )) || { error "Relancez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate losetup lsblk df blkid pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "$cmd manquant"; exit 1; }
done

# Variables globales
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPER="env_sec"
MOUNT="$HOME/env_mount"
BACKUP="$HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"
AUTO_FLAG="$HOME/.env_auto_open"
ALIAS_LINK="$HOME/.aliases_env"
LOG="/tmp/env2.log"
: >"$LOG"

# Home réel sous sudo
if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi
SSH_CONFIG="$USER_HOME/.ssh/config"

# Création dossiers
mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

# Utilitaires
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"; sleep .1
  done
  printf "\r"
}
attach_loop(){
  LOOPDEV=$(losetup --find --show "$CONTAINER")
  echo "$LOOPDEV" >"$LOOP_FILE"
  log "[OK] Loop -> $LOOPDEV"
}
detach_loop(){
  [[ -f "$LOOP_FILE" ]] && { losetup -d "$(cat "$LOOP_FILE")"; rm -f "$LOOP_FILE"; log "[OK] Loop detaché"; }
}
unlock(){
  printf '%s' "$PASS" | cryptsetup open --type luks1 --key-file=- "$1" "$MAPPER"
  log "[OK] LUKS ouvert"
}
lock_luks(){
  cryptsetup close "$MAPPER"
  log "[OK] LUKS fermé"
}
mount_env(){
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"
  log "[OK] Monté $MOUNT"
}
umount_env(){
  umount "$MOUNT" &>/dev/null || :
  log "[OK] Démonté $MOUNT"
}

show_summary(){
  whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
}

# Partie I & IV : Environnement
install_env(){
  read -p "Taille (ex:5G,500M) [${DEFAULT_SIZE}]: " SIZE; SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer   : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Passphrases diff"; exit 1; }
  log "== INSTALL ENV =="

  # écrasement
  if [[ -f "$CONTAINER" ]]; then
    if whiptail --yesno "Conteneur existe. Écraser ?" 8 50; then
      delete_env
    else
      return
    fi
  fi

  # création
  local cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
  if command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    dd if=/dev/zero bs=1M count="$cnt" >"$CONTAINER"
    log "[!pv] sans progression"
  fi
  chmod 600 "$CONTAINER"; log "[OK] Fichier $SIZE"

  # loop + LUKS + ext4 + mount
  attach_loop
  printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$LOOPDEV" --key-file=- & spinner $!
  log "[OK] LUKS formaté"
  unlock "$LOOPDEV"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  log "[OK] ext4 formaté"
  mount_env

  show_summary
}

open_env(){
  log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ERR] Conteneur introuvable"; show_summary; return; }
  attach_loop
  if [[ ! -e "/dev/mapper/$MAPPER" ]]; then
    read -s -p "Passphrase LUKS : " PASS; echo
    unlock "$LOOPDEV"
  fi
  mount_env
  show_summary
}

close_env(){
  log "== CLOSE ENV =="
  umount_env
  lock_luks
  detach_loop
  show_summary
}

delete_env(){
  log "== DELETE ENV =="
  umount_env &>/dev/null||:
  lock_luks   &>/dev/null||:
  detach_loop
  rm -f "$CONTAINER"; log "[OK] Conteneur supprimé"
  rmdir "$MOUNT" 2>/dev/null||:
  show_summary
}

backup_env(){
  log "== BACKUP ENV =="
  local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_$ts.header"
  log "[OK] Backup $BACKUP/env_$ts.{img,header}"
  show_summary
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  show_summary
}

# Partie II : GPG
gpg_setup(){
  log "== GPG SETUP =="
  read -p "Nom : " N; read -p "Email : " E; read -p "Commentaire : " C
  cat >gpg-batch <<EOF
%no-protection
Key-Type: default
Subkey-Type: default
Name-Real: $N
Name-Comment: $C
Name-Email: $E
Expire-Date: 0
%commit
EOF
  gpg --batch --generate-key gpg-batch; rm -f gpg-batch
  local key=$(gpg --list-secret-keys --with-colons|awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_$key.gpg"
  log "[OK] GPG public exporté"
  if whiptail --yesno "Exporter privé ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"
    log "[OK] GPG privé exporté"
  fi
  show_summary
}

gpg_import(){
  log "== GPG IMPORT =="
  for f in "$GPG_DIR"/*.gpg; do gpg --import "$f"; log "[OK] Import $f"; done
  show_summary
}

gpg_export(){
  gpg_setup
}

# Partie III : SSH
ssh_create_tpl(){
  log "== SSH CREATE TEMPLATE =="
  [[ ! -f "$SSH_CONFIG" ]] && { log "[ERR] Pas de $SSH_CONFIG"; show_summary; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  local H=$(whiptail --menu "Hosts" 15 50 5 "${hosts[@]/#//}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $H\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$H"
  local key=$(grep IdentityFile "$SSH_DIR/sshconf_$H" | awk '{print $2}')
  cp "$key" "$SSH_DIR/$(basename "$key")"
  sed -i "s|$key|$SSH_DIR/$(basename "$key")|" "$SSH_DIR/sshconf_$H"
  chmod 600 "$SSH_DIR/"*
  log "[OK] Template SSH $H"
  show_summary
}

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  log "[OK] Alias evsh prêt"
  show_summary
}

ssh_import_host(){ ssh_create_tpl; }
ssh_delete(){
  log "== SSH DELETE =="
  rm -rf "$SSH_DIR"/*; log "[OK] SSH vault vidé"
  show_summary
}

ssh_start(){
  log "== SSH START =="
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  [[ ${#cfgs[@]} -eq 0 ]] && { log "[ERR] Aucun SSH conf"; show_summary; return; }
  tags=(); items=()
  for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" ); items+=( "" ); done
  local CH=$(whiptail --menu "Choisir conf" 15 50 ${#tags[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$CH"
  log "[OK] SSH session terminée"
  show_summary
}

ssh_backup(){
  log "== SSH BACKUP =="
  local ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  log "[OK] SSH backup ➜ $SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz"
  show_summary
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz | xargs -n1 basename)
  local CH=$(whiptail --menu "Backup à restaurer" 15 50 5 "${bs[@]/#//}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  log "[OK] Restauré $CH"
  show_summary
}

auto_open_toggle(){
  log "== AUTO-OPEN =="
  if [[ -f "$AUTO_FLAG" ]]; then
    sed -i "\|script2.sh open_env|d" ~/.bashrc
    rm -f "$AUTO_FLAG"
    log "[OK] Auto-open désactivé"
  else
    echo "$PWD/script2.sh open_env" >>~/.bashrc
    touch "$AUTO_FLAG"
    log "[OK] Auto-open activé"
  fi
  show_summary
}

# Menu principal
if [[ "${1:-}" == "--menu" ]]; then
  while :; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      1 "Environnement" 2 "GPG" 3 "SSH" 4 "Quitter" 3>&1 1>&2 2>&3) || exit
    case $CH in
      1)
        CH2=$(whiptail --menu "Environnement" 20 60 7 \
          install_env "Installer" \
          open_env    "Ouvrir"    \
          close_env   "Fermer"    \
          delete_env  "Supprimer" \
          backup_env  "Backup"    \
          status_env  "Statut"    \
          3>&1 1>&2 2>&3) && $CH2
        ;;
      2)
        CH2=$(whiptail --menu "GPG" 15 50 3 \
          gpg_setup  "Setup" \
          gpg_import "Import"\
          gpg_export "Export"\
          3>&1 1>&2 2>&3) && $CH2
        ;;
      3)
        CH2=$(whiptail --menu "SSH" 25 60  nine \
          ssh_create_tpl     "create-template" \
          ssh_setup_alias    "setup-alias"     \
          ssh_import_host    "import-host"     \
          ssh_start          "start"           \
          ssh_delete         "delete"          \
          ssh_backup         "backup"          \
          restore_ssh_wallet "restore"         \
          auto_open_toggle   "auto-open"       \
          3>&1 1>&2 2>&3) && $CH2
        ;;
    esac
  done
else
  echo "Usage: $0 --menu"
fi
