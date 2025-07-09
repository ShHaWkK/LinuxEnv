#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Environnement Sécurisé (LUKS, ext4, backup, GPG, SSH) avec sous-menus

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & loggers ─────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
success() { echo -e "${GREEN}$*${NC}"; }
warning() { echo -e "${YELLOW}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }

# ─── Vérifications ───────────────────────────────────────────────
(( EUID==0 )) || { error "Exécutez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv whiptail gpg ssh-keygen; do
  command -v "$cmd" &>/dev/null || { error "$cmd manquant"; exit 1; }
done

# ─── Variables globales ──────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPING="env_sec"
MOUNT_POINT="$HOME/env_mount"
BACKUP_DIR="$HOME/env_backups"
SSH_BACKUP_DIR="$BACKUP_DIR/ssh_wallets"
AUTOOPEN_FLAG="$HOME/.env_auto_open"
ALIAS_LINK="$HOME/.aliases_env"

mkdir -p "${CONTAINER%/*}" "$MOUNT_POINT" "$BACKUP_DIR" "$SSH_BACKUP_DIR"

# ─── Affichages d’état ──────────────────────────────────────────
show_lsblk() { echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; echo; }
show_df()    { echo; df -Th | grep -E "$MAPPING|Filesystem" || df -Th; echo; }

# ─── Spinner pour opérations longues ─────────────────────────────
spinner() {
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[%c]${NC} " "${sp:i++%${#sp}:1}"
    sleep .1
  done; printf "\r"
}

# ─── Utilitaires ─────────────────────────────────────────────────
read_size_and_pass() {
  read -p "Taille du conteneur (ex: 5G,500M) [${DEFAULT_SIZE}]: " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS; echo
  read -s -p "Confirmer le mot de passe : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Mots de passe différents"; exit 1; }
}

attach_loop() { LOOPDEV=$(losetup --find --show "$CONTAINER"); echo "$LOOPDEV" >"$LOOP_FILE"; }
detach_loop() { [[ -f "$LOOP_FILE" ]] && { losetup -d "$(cat "$LOOP_FILE")"; rm -f "$LOOP_FILE"; }; }
unlock_volume()  { printf '%s' "$PASS" | cryptsetup open --type luks1 --key-file=- "$1" "$MAPPING"; }
lock_volume()    { cryptsetup close "$MAPPING"; }
mount_volume()   { mount "/dev/mapper/$MAPPING" "$MOUNT_POINT"; }
umount_volume()  { umount "$MOUNT_POINT" &>/dev/null || :; }

# ─── Environnement ───────────────────────────────────────────────
install_env() {
  info "INSTALL"; show_lsblk; read_size_and_pass
  [[ -f "$CONTAINER" ]] && { error "Conteneur existe"; return; }
  cryptsetup status "$MAPPING" &>/dev/null && { error "Mapping existe"; return; }
  local cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création ($SIZE)…"; dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  show_lsblk; info "Attach…"; attach_loop; show_lsblk
  info "LUKS format (YES)…"; printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$LOOPDEV" --key-file=- "$LOOPDEV" & spinner $!; show_lsblk
  info "Open…"; unlock_volume "$LOOPDEV"; show_lsblk
  info "mkfs.ext4…"; mkfs.ext4 "/dev/mapper/$MAPPING" & spinner $!; show_lsblk
  info "Mount…"; mount_volume; chmod 600 "$CONTAINER"; chmod -R go-rwx "$MOUNT_POINT"; show_lsblk; show_df
  success "Installé ➜ $MOUNT_POINT"
}
open_env() {
  info "OPEN"; show_lsblk
  [[ ! -f "$CONTAINER" ]] && { error "Pas de conteneur"; return; }
  [[ ! -f "$LOOP_FILE" ]] && attach_loop
  if [[ ! -e "/dev/mapper/$MAPPING" ]]; then
    read -s -p "Passphrase LUKS : " PASS; echo
    unlock_volume "$(cat "$LOOP_FILE")"; success "Volume déverrouillé"
  fi
  mount_volume; chmod -R go-rwx "$MOUNT_POINT"; show_lsblk; show_df; success "Ouvert"
}
close_env() {
  info "CLOSE"; umount_volume && success "Démonté"
  [[ -e "/dev/mapper/$MAPPING" ]] && lock_volume && success "Verrouillé"
  detach_loop && success "Loop détaché"; show_lsblk
}
delete_env() {
  info "DELETE"; close_env; rm -f "$CONTAINER"; rmdir "$MOUNT_POINT" &>/dev/null || :; show_lsblk; success "Supprimé"
}
backup_env() {
  info "BACKUP ENV"; local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP_DIR/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP_DIR/env_$ts.header"
  success "Sauvegardes ➜ $BACKUP_DIR"
}
status_env() {
  info "STATUS"; show_lsblk; show_df
  blkid "/dev/mapper/$MAPPING" &>/dev/null && blkid "/dev/mapper/$MAPPING"
}

# ─── GPG ─────────────────────────────────────────────────────────
gpg_setup() {
  info "GPG SETUP"; read -p "Nom : " NAME; read -p "Email : " EMAIL; read -p "Commentaire : " COMMENT
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
  gpg --batch --generate-key gpg-batch; rm -f gpg-batch
  local key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$MOUNT_POINT/public_$key.gpg"
  gpg --export-secret-keys --armor "$key" >"$MOUNT_POINT/private_$key.gpg"
  chmod 600 "$MOUNT_POINT/private_$key.gpg"; success "Clés GPG exportées"
}
gpg_import() {
  info "GPG IMPORT"; for f in "$MOUNT_POINT"/*.gpg; do gpg --import "$f" && success "Importé $f"; done
}
gpg_export() {
  info "GPG EXPORT"; for key in $(gpg --list-secret-keys --with-colons|awk -F: '/^sec/ {print $5}'); do
    gpg --export --armor "$key" >"$MOUNT_POINT/public_$key.gpg"
    gpg --export-secret-keys --armor "$key" >"$MOUNT_POINT/private_$key.gpg"
    chmod 600 "$MOUNT_POINT/private_$key.gpg"; success "Exporté $key"
  done
}

# ─── SSH ─────────────────────────────────────────────────────────
ssh_create_template() {
  info "SSH CREATE TEMPLATE"
  mapfile -t hosts < <(grep '^Host ' ~/.ssh/config | awk '{print $2}')
  CH=$(whiptail --menu "Choisir Host" 15 60 5 "${hosts[@]/#//}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $CH\$/,/^Host /" ~/.ssh/config >"$MOUNT_POINT/ssh_config_$CH"
  success "Template ➜ ssh_config_$CH"
}
ssh_import_host() {
  info "SSH IMPORT HOST"; mkdir -p "$MOUNT_POINT/ssh_hosts"
  cp ~/.ssh/id_rsa* "$MOUNT_POINT/ssh_hosts/" 2>/dev/null || :
  cp ~/.ssh/config "$MOUNT_POINT/ssh_hosts/" 2>/dev/null || :
  success "Copié ➜ ssh_hosts"
}
ssh_setup_alias() {
  info "SSH SETUP ALIAS"; echo "alias evsh='ssh -F $MOUNT_POINT/ssh_config_*'" >"$ALIAS_LINK"
  success "Alias evsh prêt"
}
ssh_start() {
  info "SSH START"
  mapfile -t cfgs < <(ls "$MOUNT_POINT"/ssh_config_* | xargs -n1 basename)
  C=$(whiptail --menu "Choisir config" 15 60 5 "${cfgs[@]/#//}" 3>&1 1>&2 2>&3) || return
  ssh -F "$MOUNT_POINT/$C"
}
ssh_delete() {
  info "SSH DELETE"; rm -rf "$MOUNT_POINT"/ssh_config_* "$MOUNT_POINT/ssh_hosts"; success "Supprimé"
}
ssh_backup() {
  info "SSH BACKUP"; local ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$MOUNT_POINT" ssh_config_* ssh_hosts
  success "Backup ➜ $SSH_BACKUP_DIR"
}
restore_ssh_wallet() {
  info "RESTORE SSH WALLET"
  mapfile -t bps < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz|xargs -n1 basename)
  F=$(whiptail --menu "Choisir backup" 15 60 5 "${bps[@]/#//}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$F" -C "$MOUNT_POINT"; success "Restauré ➜ $F"
}
auto_open_toggle() {
  info "AUTO-OPEN"
  if [[ -f "$AUTOOPEN_FLAG" ]]; then
    rm -f "$AUTOOPEN_FLAG"; sed -i "\|env.sh open|d" ~/.bashrc
    success "Auto-open désactivé"
  else
    touch "$AUTOOPEN_FLAG"; echo "$PWD/env.sh open &>/dev/null" >>~/.bashrc
    success "Auto-open activé"
  fi
}

# ─── Sous-menus & menu principal ─────────────────────────────────
main_menu() {
  CH=$(whiptail --title "Menu principal" --menu "Choisissez une section" \
    15 60 4 \
    1 "Environnement" \
    2 "GPG" \
    3 "SSH" \
    4 "Quitter" \
    3>&1 1>&2 2>&3) || exit
  case $CH in
    1) env_menu ;;
    2) gpg_menu ;;
    3) ssh_menu ;;
    4) exit 0 ;;
  esac
  main_menu
}

env_menu() {
  CH=$(whiptail --title "Environnement" --menu "Actions" \
    20 60 6 \
    install_env "Installer" \
    open_env    "Ouvrir" \
    close_env   "Fermer" \
    delete_env  "Supprimer" \
    backup_env  "Backup env" \
    status_env  "Statut" \
    3>&1 1>&2 2>&3) || return
  $CH; whiptail --msgbox "Terminé." 8 40
}

gpg_menu() {
  CH=$(whiptail --title "GPG" --menu "Actions" \
    15 60 4 \
    gpg_setup  "Setup" \
    gpg_import "Import" \
    gpg_export "Export" \
    3>&1 1>&2 2>&3) || return
  $CH; whiptail --msgbox "Terminé." 8 40
}

ssh_menu() {
  CH=$(whiptail --title "SSH" --menu "Actions" \
    25 60 9 \
    ssh_create_template "ssh-create-template" \
    ssh_import_host    "ssh-import-host" \
    ssh_setup_alias    "ssh-setup-alias" \
    ssh_start          "ssh-start" \
    ssh_delete         "ssh-delete" \
    ssh_backup         "ssh-backup" \
    restore_ssh_wallet "restore-ssh-wallet" \
    auto_open_toggle   "auto-open" \
    3>&1 1>&2 2>&3) || return
  $CH; whiptail --msgbox "Terminé." 8 40
}

# ────────────────────────────────────────────────────────────────
# Lancement du menu
# ────────────────────────────────────────────────────────────────
main_menu
