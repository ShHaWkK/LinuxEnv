#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Coffre Sécurisé (LUKS, ext4, GPG, SSH) avec menus thématiques

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs ────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
success() { echo -e "${GREEN}$*${NC}"; }
warning() { echo -e "${YELLOW}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }

# ─── Vérifs ─────────────────────────────────────────────────────
(( EUID==0 )) || { error "Exécutez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv whiptail gpg ssh-keygen; do
  command -v "$cmd" &>/dev/null || { error "$cmd manquant"; exit 1; }
done

# ─── Variables ───────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPING="env_sec"
MOUNT_POINT="$HOME/env_mount"
BACKUP_DIR="$HOME/env_backups"
SSH_DIR="$MOUNT_POINT/ssh"
GPG_DIR="$MOUNT_POINT/gpg"
SSH_BACKUP_DIR="$BACKUP_DIR/ssh_wallets"
AUTOOPEN_FLAG="$HOME/.env_auto_open"
ALIAS_LINK="$HOME/.aliases_env"

mkdir -p "${CONTAINER%/*}" "$MOUNT_POINT" "$BACKUP_DIR" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

# ─── Affichages ─────────────────────────────────────────────────
show_lsblk(){ echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; echo; }
show_df(){ echo; df -Th | grep -E "$MAPPING|Filesystem" || df -Th; echo; }

# ─── Spinner ────────────────────────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[%c]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done; printf "\r"
}

# ─── Utilitaires ─────────────────────────────────────────────────
read_size_and_pass(){
  read -p "Taille conteneur [${DEFAULT_SIZE}]: " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS; echo
  read -s -p "Exporter la clé privée ? [y/N]: " EXP_PRIV; echo
  read -s -p "Confirmer : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Mots de passe différents"; exit 1; }
}

attach_loop(){ LOOPDEV=$(losetup --find --show "$CONTAINER"); echo "$LOOPDEV" >"$LOOP_FILE"; }
detach_loop(){ [[ -f "$LOOP_FILE" ]] && { losetup -d "$(cat "$LOOP_FILE")"; rm -f "$LOOP_FILE"; }; }
unlock_volume(){ printf '%s' "$PASS" | cryptsetup open --key-file=- "$1" "$MAPPING"; }
lock_volume(){ cryptsetup close "$MAPPING"; }
mount_volume(){ mount "/dev/mapper/$MAPPING" "$MOUNT_POINT"; }
umount_volume(){ umount "$MOUNT_POINT" &>/dev/null || :; }

# ─── Environnement ───────────────────────────────────────────────
install_env(){
  info "INSTALL"; show_lsblk; read_size_and_pass
  [[ -f "$CONTAINER" ]] && { error "Conteneur existe"; return; }
  cryptsetup status "$MAPPING" &>/dev/null && { error "Mapping existe"; return; }
  cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création ($SIZE)";
    dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  chmod 600 "$CONTAINER"; show_lsblk
  info "Attach loop"; attach_loop; show_lsblk
  info "LUKS format (tapez YES)"; printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$LOOPDEV" --key-file=- & spinner $!
  show_lsblk; info "Open"; unlock_volume "$LOOPDEV"; show_lsblk
  info "mkfs.ext4"; mkfs.ext4 "/dev/mapper/$MAPPING" & spinner $!; show_lsblk
  info "Mount"; mount_volume; chmod -R go-rwx "$MOUNT_POINT"; show_lsblk; show_df
  success "Installé ➜ $MOUNT_POINT"
}
open_env(){
  info "OPEN"; show_lsblk
  [[ ! -f "$CONTAINER" ]] && { error "Pas de conteneur"; return; }
  [[ ! -f "$LOOP_FILE" ]] && attach_loop
  [[ ! -e "/dev/mapper/$MAPPING" ]] && { read -s -p "Passphrase LUKS : " PASS; echo; unlock_volume "$(cat "$LOOP_FILE")"; }
  mount_volume; chmod -R go-rwx "$MOUNT_POINT"; show_lsblk; show_df; success "Ouvert"
}
close_env(){
  info "CLOSE"; umount_volume && success "Démonté"
  [[ -e "/dev/mapper/$MAPPING" ]] && lock_volume && success "Verrouillé"
  detach_loop && success "Loop détaché"; show_lsblk
}
delete_env(){
  info "DELETE"; close_env; rm -f "$CONTAINER"; rmdir "$MOUNT_POINT" &>/dev/null || :; show_lsblk; success "Supprimé"
}
backup_env(){
  info "BACKUP ENV"; ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP_DIR/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP_DIR/env_$ts.header"
  success "Sauvegardé env+header ➜ $BACKUP_DIR"
}
status_env(){
  info "STATUS"; show_lsblk; show_df
  blkid "/dev/mapper/$MAPPING" &>/dev/null && blkid "/dev/mapper/$MAPPING"
}

# ─── Cryptographie GPG ───────────────────────────────────────────
gpg_setup(){
  info "GPG SETUP"; read -p "Nom : " NAME; read -p "Email : " EMAIL; read -p "Comment : " COMMENT
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
  key=$(gpg --list-secret-keys --with-colons|awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_$key.gpg"
  [[ $EXP_PRIV =~ ^[Yy]$ ]] && { \
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"; \
    chmod 600 "$GPG_DIR/private_$key.gpg"; \
  }
  chmod 644 "$GPG_DIR/public_$key.gpg"
  success "GPG clés exportées ➜ $GPG_DIR"
}
gpg_import(){
  info "GPG IMPORT"; for f in "$GPG_DIR"/*.gpg; do gpg --import "$f" && success "Importé $f"; done
}
gpg_export(){
  info "GPG EXPORT"; for key in $(gpg --list-secret-keys --with-colons|awk -F: '/^sec/ {print $5}'); do
    gpg --export --armor "$key" >"$GPG_DIR/public_$key.gpg"
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"; chmod 644 "$GPG_DIR/public_$key.gpg"
    success "Exporté $key"
  done
}

# ─── Configuration SSH ───────────────────────────────────────────
ssh_create_template(){
  info "SSH TEMPLATE"
  mapfile -t hosts < <(grep '^Host ' ~/.ssh/config|awk '{print $2}')
  CH=$(whiptail --menu "Choisir host" 15 60 5 "${hosts[@]/#//}" 3>&1 1>&2 2>&3) || return
  # extrait conf et copie clé
  awk "/^Host $CH\$/,/^Host /" ~/.ssh/config >"$SSH_DIR/ssh_config_$CH"
  key=$(grep IdentityFile "$SSH_DIR/ssh_config_$CH"|awk '{print $2}')
  cp "$key" "$SSH_DIR/$(basename "$key")"
  sed -i "s|$key|$SSH_DIR/$(basename "$key")|" "$SSH_DIR/ssh_config_$CH"
  chmod 600 "$SSH_DIR/$(basename "$key")" "$SSH_DIR/ssh_config_$CH"
  chmod 644 "$SSH_DIR/$(basename "$key").pub"
  success "Config+clé ➜ $SSH_DIR/ssh_config_$CH"
}
ssh_setup_alias(){
  info "SSH ALIAS"; echo "alias evsh='ssh -F $SSH_DIR/ssh_config_*'" >"$ALIAS_LINK"; success "Alias prêt"
}
ssh_import_host(){
  info "SSH IMPORT HOST"; ssh_create_template
}
ssh_start(){
  info "SSH START"
  mapfile -t cfgs < <(ls "$SSH_DIR"/ssh_config_*)
  C=$(whiptail --menu "Choisir config" 15 60 5 "${cfgs[@]/#//}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$C"
}
ssh_delete(){
  info "SSH DELETE"; rm -rf "$SSH_DIR"/ssh_config_* "$SSH_DIR"/$(basename *) ; success "Supprimé"
}
ssh_backup(){
  info "SSH BACKUP"; ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .; success "Backup ➜ $SSH_BACKUP_DIR"
}
restore_ssh_wallet(){
  info "SSH RESTORE"
  mapfile -t backs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz|xargs -n1 basename)
  F=$(whiptail --menu "Choisir backup" 15 60 5 "${backs[@]/#//}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$F" -C "$SSH_DIR"; success "Restauré ➜ $F"
}
auto_open_toggle(){
  info "AUTO-OPEN"
  if [[ -f "$AUTOOPEN_FLAG" ]]; then
    rm -f "$AUTOOPEN_FLAG"; sed -i "\|env.sh open|d" ~/.bashrc; success "Désactivé"
  else
    touch "$AUTOOPEN_FLAG"; echo "$PWD/env.sh open" >>~/.bashrc; success "Activé"
  fi
}

# ─── Menus ───────────────────────────────────────────────────────
env_menu(){
  CH=$(whiptail --title "Environnement" --menu "Actions" 20 60 6 \
    install_env "Installer" open_env "Ouvrir" close_env "Fermer" \
    delete_env "Supprimer" backup_env "Backup" status_env "Statut" 3>&1 1>&2 2>&3)||return
  $CH; whiptail --msgbox "OK" 6 30
}
gpg_menu(){
  CH=$(whiptail --title "GPG" --menu "Crypto" 15 60 3 \
    gpg_setup "Setup" gpg_import "Import" gpg_export "Export" 3>&1 1>&2 2>&3)||return
  $CH; whiptail --msgbox "OK" 6 30
}
ssh_menu(){
  CH=$(whiptail --title "SSH" --menu "Config SSH" 25 60 8 \
    ssh_create_template "create-template" ssh_import_host "import-host" \
    ssh_setup_alias "setup-alias" ssh_start "start" ssh_delete "delete" \
    ssh_backup "backup" restore_ssh_wallet "restore" auto_open_toggle "auto-open" \
    3>&1 1>&2 2>&3)||return
  $CH; whiptail --msgbox "OK" 6 30
}
main_menu(){
  while :;do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      1 "Environnement" 2 "GPG" 3 "SSH" 4 "Quitter" 3>&1 1>&2 2>&3)||exit
    case $CH in
      1) env_menu ;;
      2) gpg_menu ;;
      3) ssh_menu ;;
      4) exit 0 ;;
    esac
  done
}

main_menu
