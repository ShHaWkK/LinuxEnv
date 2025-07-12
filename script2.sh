#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Coffre Sécurisé (LUKS, ext4, GPG, SSH) – complet & intuitif

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

### Couleurs & logs ###
RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
success() { echo -e "${GREEN}$*${NC}"; }
warning() { echo -e "${YELLOW}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }

### Vérifications ###
(( EUID==0 )) || { error "Exécutez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv whiptail gpg ssh-keygen; do
  command -v "$cmd" >/dev/null 2>&1 || { error "$cmd manquant"; exit 1; }
done

### Variables ###
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPER="env_sec"
MOUNT="$HOME/env_mount"
BACKUP="$HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"
AUTOOPEN_FLAG="$HOME/.env_auto_open"
ALIAS_LINK="$HOME/.aliases_env"

mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

### Affichage état ###
show_lsblk(){ echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; echo; }
show_df(){ echo; df -Th | grep -E "$MAPPER|Filesystem" || df -Th; echo; }

### Spinner ###
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[%c]${NC}" "${sp:i++%${#sp}:1}"; sleep .1
  done
  printf "\r"
}

### Utils ###
ask_pass(){
  read -p "Taille (5G,500M) [${DEFAULT_SIZE}]: " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS;   echo
  read -s -p "Confirmer mot de passe  : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Mots de passe différents"; exit 1; }
  read -s -p "Exporter clé privée GPG ? [y/N]: " EXP_PRIV; echo
}

attach_loop(){
  LOOPDEV=$(losetup --find --show "$CONTAINER")
  echo "$LOOPDEV" >"$LOOP_FILE"
}
detach_loop(){
  [[ -f "$LOOP_FILE" ]] && { losetup -d "$(cat "$LOOP_FILE")"; rm -f "$LOOP_FILE"; }
}

unlock(){
  printf '%s' "$PASS" | cryptsetup open --type luks1 --key-file=- "$1" "$MAPPER"
}
lock(){
  cryptsetup close "$MAPPER"
}
mount_env(){
  mount "/dev/mapper/$MAPPER" "$MOUNT"
}
umount_env(){
  umount "$MOUNT" &>/dev/null || :
}

### Environnement ###
install_env(){
  info "INSTALL ENVIRONNEMENT"; show_lsblk; ask_pass
  [[ -f "$CONTAINER" ]] && { error "Conteneur existe"; return; }
  cryptsetup status "$MAPPER" &>/dev/null && { error "Mapping existe"; return; }
  local cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))

  info "Création fichier ($SIZE)…"
  if command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    warning "pv non installé → dd sans barre"
    dd if=/dev/zero bs=1M count="$cnt" >"$CONTAINER"
  fi
  chmod 600 "$CONTAINER"; show_lsblk

  info "Attacher loop"
  attach_loop; show_lsblk

  info "Initialisation LUKS (tapez YES)…"
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --type luks1 --batch-mode "$LOOPDEV" --key-file=- \
    & spinner $!; show_lsblk

  info "Ouverture volume"
  unlock "$LOOPDEV"; show_lsblk

  info "Format ext4"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!; show_lsblk

  info "Montage"
  mount_env; chmod -R go-rwx "$MOUNT"; show_lsblk; show_df

  success "Env prêt ➜ $MOUNT"
}

open_env(){
  info "OUVERTURE ENV"
  [[ ! -f "$CONTAINER" ]] && { error "Pas de conteneur"; return; }
  [[ ! -f "$LOOP_FILE" ]] && attach_loop
  if [[ ! -e "/dev/mapper/$MAPPER" ]]; then
    read -s -p "Passphrase LUKS : " PASS; echo
    unlock "$(cat "$LOOP_FILE")"
  fi
  mount_env; chmod -R go-rwx "$MOUNT"; show_lsblk; show_df; success "Env ouvert"
}

close_env(){
  info "FERMETURE ENV"
  umount_env && success "Démonté"
  [[ -e "/dev/mapper/$MAPPER" ]] && { lock; success "Verrouillé"; }
  detach_loop && success "Loop détaché"; show_lsblk
}

delete_env(){
  info "SUPPRESSION ENV"
  close_env
  rm -f "$CONTAINER"
  rmdir "$MOUNT" &>/dev/null || :
  show_lsblk; success "Env supprimé"
}

backup_env(){
  info "BACKUP ENV"
  local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_$ts.header"
  success "Backup env+header ➜ $BACKUP"
}

status_env(){
  info "STATUT ENV"; show_lsblk; show_df
  blkid "/dev/mapper/$MAPPER" &>/dev/null && blkid "/dev/mapper/$MAPPER"
}

### GPG ###
gpg_setup(){
  info "GPG SETUP"
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

  local key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key"       >"$GPG_DIR/public_$key.gpg"
  if [[ $EXP_PRIV =~ ^[Yy]$ ]]; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"
  fi
  chmod 644 "$GPG_DIR/public_$key.gpg"
  success "Clés GPG exportées ➜ $GPG_DIR"
}

gpg_import(){
  info "GPG IMPORT"
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && success "Importé $f"
  done
}

gpg_export(){
  info "GPG EXPORT"
  for key in $(gpg --list-secret-keys --with-colons| awk -F: '/^sec/ {print $5}'); do
    gpg --export --armor "$key"       >"$GPG_DIR/public_$key.gpg"
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"
    chmod 644 "$GPG_DIR/public_$key.gpg"
    success "Exporté GPG clé $key"
  done
}

### SSH ###
ssh_create_tpl(){
  info "SSH CREATE-TEMPLATE"
  mapfile -t hosts < <(grep '^Host ' ~/.ssh/config | awk '{print $2}')
  local H=$(whiptail --menu "Choisissez host" 15 60 5 "${hosts[@]/#//}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $H\$/,/^Host /" ~/.ssh/config >"$SSH_DIR/sshconf_$H"
  local key=$(grep IdentityFile "$SSH_DIR/sshconf_$H" | awk '{print $2}')
  cp "$key" "$SSH_DIR/$(basename "$key")"
  sed -i "s|$key|$SSH_DIR/$(basename "$key")|" "$SSH_DIR/sshconf_$H"
  chmod 600 "$SSH_DIR/$(basename "$key")" "$SSH_DIR/sshconf_$H"
  success "Config+clé ➜ sshconf_$H"
}

ssh_setup_alias(){
  info "SSH SETUP-ALIAS"
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  success "Alias evsh prêt"
}

ssh_import_host(){
  ssh_create_tpl
}

ssh_start(){
  info "SSH START"
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_*)
  local C=$(whiptail --menu "Choisissez config" 15 60 5 "${cfgs[@]/#//}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$C"
}

ssh_delete(){
  info "SSH DELETE"
  rm -rf "$SSH_DIR"/sshconf_* "$SSH_DIR"/$(basename *) &>/dev/null || :
  success "SSH supprimé"
}

ssh_backup(){
  info "SSH BACKUP"
  local ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  success "SSH backup ➜ $SSH_BACKUP_DIR"
}

restore_ssh_wallet(){
  info "SSH RESTORE"
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz | xargs -n1 basename)
  local B=$(whiptail --menu "Choisissez backup" 15 60 5 "${bs[@]/#//}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$B" -C "$SSH_DIR"
  success "Restauré ➜ $B"
}

auto_open_toggle(){
  info "AUTO-OPEN"
  if [[ -f "$AUTOOPEN_FLAG" ]]; then
    sed -i "\|env.sh open_env|d" ~/.bashrc
    rm -f "$AUTOOPEN_FLAG"
    success "Auto-open désactivé"
  else
    echo "$PWD/env.sh open_env" >>~/.bashrc
    touch "$AUTOOPEN_FLAG"
    success "Auto-open activé"
  fi
}

### Menus ###
env_menu(){
  CH=$(whiptail --title "Environnement" --menu "Action" 20 60 6 \
    install_env "Installer" \
    open_env    "Ouvrir" \
    close_env   "Fermer" \
    delete_env  "Supprimer" \
    backup_env  "Backup" \
    status_env  "Statut" \
  3>&1 1>&2 2>&3)|| return
  $CH; whiptail --msgbox "Terminé" 6 30
}

gpg_menu(){
  CH=$(whiptail --title "GPG" --menu "Crypto" 15 60 3 \
    gpg_setup  "Setup" \
    gpg_import "Import" \
    gpg_export "Export" \
  3>&1 1>&2 2>&3)|| return
  $CH; whiptail --msgbox "Terminé" 6 30
}

ssh_menu(){
  CH=$(whiptail --title "SSH" --menu "Config SSH" 25 60 8 \
    ssh_create_tpl     "create-template" \
    ssh_import_host    "import-host" \
    ssh_setup_alias    "setup-alias" \
    ssh_start          "start" \
    ssh_delete         "delete" \
    ssh_backup         "backup" \
    restore_ssh_wallet "restore" \
    auto_open_toggle   "auto-open" \
  3>&1 1>&2 2>&3)|| return
  $CH; whiptail --msgbox "Terminé" 6 30
}

main_menu(){
  while :; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      1 "Environnement" \
      2 "GPG" \
      3 "SSH" \
      4 "Quitter" \
    3>&1 1>&2 2>&3)|| exit
    case $CH in
      1) env_menu  ;;
      2) gpg_menu  ;;
      3) ssh_menu  ;;
      4) exit 0    ;;
    esac
  done
}

main_menu
