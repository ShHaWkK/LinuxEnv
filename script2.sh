#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Coffre Sécurisé (LUKS, ext4, GPG, SSH) – complet, menu & vérifs

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ══ Couleurs ════════════════════════════════════════════════════════
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
success() { echo -e "${GREEN}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }

# ══ Vérifs préalables ═════════════════════════════════════════════
(( EUID==0 )) || { error "Relancez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv whiptail gpg ssh-keygen; do
  command -v "$cmd" &>/dev/null || { error "$cmd introuvable"; exit 1; }
done

# ══ Variables ══════════════════════════════════════════════════════
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
EXP_PRIV="N"   # initialisé pour éviter unbound variable

# Détecte le vrai SSH config de l’utilisateur initial
if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi
SSH_CONFIG="$USER_HOME/.ssh/config"

mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

# ══ Affichage état ═════════════════════════════════════════════════
show_lsblk(){ lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; }
show_df(){ df -Th | grep -E "$MAPPER|Filesystem" || df -Th; }

# ══ Spinner ════════════════════════════════════════════════════════
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"; sleep .1
  done
  printf "\r"
}

# ══ Wrappers & utilitaires ═════════════════════════════════════════
ask_pass(){
  read -p "Taille (ex:5G,500M) [${DEFAULT_SIZE}]: " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS; echo
  read -s -p "Confirmer : " PASS2; echo
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

# ══ Vérification post-action ══════════════════════════════════════
verify(){
  local label=$1; shift
  if "$@"; then
    whiptail --msgbox "${label} : Succès" 6 40
  else
    whiptail --msgbox "${label} : Erreur" 6 40
  fi
}

# ══ Partie I & IV : Environnement ═════════════════════════════════
install_env(){
  info "--- INSTALL ENVIRONNEMENT ---"
  ask_pass
  if [[ -f "$CONTAINER" ]]; then
    if ! whiptail --yesno "Conteneur existe. Écraser ?" 8 40; then
      return
    fi
    delete_env
  fi
  [[ $(cryptsetup status "$MAPPER" 2>/dev/null) ]] && { error "Mapping existant"; return; }

  # 1) Création fichier
  local cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
  if command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    dd if=/dev/zero bs=1M count="$cnt" >"$CONTAINER"
  fi
  chmod 600 "$CONTAINER"
  verify "Création fichier" test -f "$CONTAINER"

  # 2) Attach loop
  attach_loop
  verify "Attach loop" grep -q "$(cat "$LOOP_FILE")" /proc/partitions

  # 3) LUKS format
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --type luks1 --batch-mode "$(cat "$LOOP_FILE")" --key-file=- & spinner $!
  verify "Format LUKS" cryptsetup isLuks "$(cat "$LOOP_FILE")"

  # 4) Open LUKS
  unlock "$(cat "$LOOP_FILE")"
  verify "Ouverture LUKS" [[ -e /dev/mapper/$MAPPER ]]

  # 5) mkfs.ext4
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  verify "Format ext4" blkid /dev/mapper/$MAPPER

  # 6) Montage
  mount_env; chmod -R go-rwx "$MOUNT"
  verify "Montage" mountpoint -q "$MOUNT"
}

open_env(){
  info "--- OPEN ENVIRONNEMENT ---"
  [[ ! -f "$CONTAINER" ]] && { whiptail --msgbox "Pas de conteneur" 6 30; return; }
  attach_loop || true
  if [[ ! -e "/dev/mapper/$MAPPER" ]]; then
    read -s -p "Passphrase LUKS : " PASS; echo
    unlock "$(cat "$LOOP_FILE")"
  fi
  mount_env
  verify "Ouverture+Montage" mountpoint -q "$MOUNT"
}

close_env(){
  info "--- CLOSE ENVIRONNEMENT ---"
  umount_env
  verify "Unmount" ! mountpoint -q "$MOUNT"
  lock
  verify "Fermeture LUKS" ! cryptsetup status "$MAPPER" | grep -q "is active"
  detach_loop
  verify "Détach loop" [[ ! -f "$LOOP_FILE" ]]
}

delete_env(){
  info "--- DELETE ENVIRONNEMENT ---"
  close_env || true
  rm -f "$CONTAINER"
  rmdir "$MOUNT" &>/dev/null || :
  verify "Suppression fichier" [[ ! -f "$CONTAINER" ]]
}

backup_env(){
  info "--- BACKUP ENVIRONNEMENT ---"
  local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_$ts.header"
  verify "Backup env" [[ -f "$BACKUP/env_$ts.img" ]] && [[ -f "$BACKUP/env_$ts.header" ]]
}

status_env(){
  info "--- STATUS ENVIRONMENT ---"
  show_lsblk; show_df
  whiptail --msgbox "Regardez le terminal pour l'état." 6 50
}

# ══ Partie II : GPG ══════════════════════════════════════════════
gpg_setup(){
  info "--- GPG SETUP ---"
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
  gpg --export --armor "$key"       >"$GPG_DIR/public_$key.gpg"
  if [[ $EXP_PRIV =~ ^[Yy]$ ]]; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"
  fi
  chmod 644 "$GPG_DIR/public_$key.gpg"
  verify "Export GPG" [[ -f "$GPG_DIR/public_$key.gpg" ]]
}

gpg_import(){
  info "--- GPG IMPORT ---"
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f"
  done
  whiptail --msgbox "Import GPG terminé." 6 40
}

gpg_export(){
  gpg_setup
}

# ══ Partie III : SSH ════════════════════════════════════════════
ssh_create_tpl(){
  info "--- SSH CREATE TEMPLATE ---"
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de $SSH_CONFIG" 6 40; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG"|awk '{print $2}')
  local H=$(whiptail --menu "Choisissez host" 15 60 5 "${hosts[@]/#//}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $H\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$H"
  local key=$(grep IdentityFile "$SSH_DIR/sshconf_$H" | awk '{print $2}')
  cp "$key" "$SSH_DIR/$(basename "$key")"
  sed -i "s|$key|$SSH_DIR/$(basename "$key")|" "$SSH_DIR/sshconf_$H"
  chmod 600 "$SSH_DIR/$(basename "$key")" "$SSH_DIR/sshconf_$H"
  verify "SSH template" [[ -f "$SSH_DIR/sshconf_$H" ]]
}

ssh_setup_alias(){
  info "--- SSH SETUP ALIAS ---"
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  verify "Alias evsh" grep -q "evsh=" "$ALIAS_LINK"
}

ssh_import_host(){
  ssh_create_tpl
}

ssh_start(){
  info "--- SSH START ---"
  local files=( "$SSH_DIR"/sshconf_* )
  [[ ${#files[@]} -eq 0 ]] && { whiptail --msgbox "Aucune config SSH"`
  return; }
  local tags=() items=()
  for f in "${files[@]}"; do
    tags+=( "$(basename "$f")" )
    items+=( "" )
  done
  local CH=$(whiptail --menu "Choisissez config" 15 60 ${#tags[@]} \
    "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$CH"
  whiptail --msgbox "SSH terminé." 6 40
}

ssh_delete(){
  info "--- SSH DELETE ---"
  rm -rf "$SSH_DIR"/sshconf_* "$SSH_DIR"/*
  verify "SSH delete" [[ -z $(ls -A "$SSH_DIR") ]]
}

ssh_backup(){
  info "--- SSH BACKUP ---"
  local ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  verify "SSH backup" [[ -f "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" ]]
}

restore_ssh_wallet(){
  info "--- SSH RESTORE ---"
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz|xargs -n1 basename)
  local CH=$(whiptail --menu "Choisissez backup" 15 60 5 "${bs[@]/#//}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  verify "SSH restore" [[ -n $(ls -A "$SSH_DIR") ]]
}

auto_open_toggle(){
  info "--- AUTO-OPEN ---"
  if [[ -f "$AUTO_FLAG" ]]; then
    sed -i "\|env.sh open_env|d" ~/.bashrc
    rm -f "$AUTO_FLAG"
    whiptail --msgbox "Auto-open désactivé" 6 40
  else
    echo "$PWD/env.sh open_env" >>~/.bashrc
    touch "$AUTO_FLAG"
    whiptail --msgbox "Auto-open activé" 6 40
  fi
}

# ══ Mode menu si --menu ══════════════════════════════════════════
if [[ "${1:-}" == "--menu" || "${1:-}" == "-m" ]]; then
  while :; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      1 "Environnement" \
      2 "GPG"         \
      3 "SSH"         \
      4 "Quitter"     \
      3>&1 1>&2 2>&3) || exit
    case $CH in
      1)
        CH2=$(whiptail --menu "Environnement" 20 60 6 \
          install_env "Installer" \
          open_env    "Ouvrir"    \
          close_env   "Fermer"    \
          delete_env  "Supprimer" \
          backup_env  "Backup"    \
          status_env  "Statut"    \
          3>&1 1>&2 2>&3) && $CH2
        ;;
      2)
        CH2=$(whiptail --menu "GPG" 15 60 3 \
          gpg_setup  "Setup" \
          gpg_import "Import"\
          gpg_export "Export"\
          3>&1 1>&2 2>&3) && $CH2
        ;;
      3)
        CH2=$(whiptail --menu "SSH" 25 60 8 \
          ssh_create_tpl     "create-template" \
          ssh_import_host    "import-host"     \
          ssh_setup_alias    "setup-alias"     \
          ssh_start          "start"           \
          ssh_delete         "delete"          \
          ssh_backup         "backup"          \
          restore_ssh_wallet "restore"         \
          auto_open_toggle   "auto-open"       \
          3>&1 1>&2 2>&3) && $CH2
        ;;
      4)
        exit 0
        ;;
    esac
  done
fi

cat <<EOF
Usage: $0 --menu
EOF
