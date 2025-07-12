#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Coffre Sécurisé complet (LUKS, ext4, GPG, SSH)

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & utilitaires ────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }
log()     { echo "$*" >>"$LOG"; }

# ─── Vérif root + dépendances ─────────────────────────────────────────────
(( EUID==0 )) || { error "Relancez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate lsblk df blkid pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "$cmd manquant"; exit 1; }
done

# ─── Variables globales ────────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
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

mkdir -p "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

# ─── Spinner ───────────────────────────────────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

# ─── Résumé ─────────────────────────────────────────────────────────────────
show_summary(){
  whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
}

# ─── Cryptographie (Partie II) ───────────────────────────────────────────────
gpg_setup(){
  log "== GPG SETUP =="
  read -p "Nom        : " N
  read -p "Email      : " E
  read -p "Commentaire: " C
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
  gpg --batch --generate-key gpg-batch && rm -f gpg-batch
  key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_$key.gpg"
  log "[OK] Public GPG exported"
  if whiptail --yesno "Exporter clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"
    log "[OK] Privé GPG exported"
  fi
  show_summary
}

gpg_import(){
  log "== GPG IMPORT =="
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] Import $f"
  done
  show_summary
}

# ─── Environnement (Partie I & IV) ─────────────────────────────────────────┐
ask_pass(){
  read -p "Taille (ex:5G,500M) [${DEFAULT_SIZE}]: " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Passphrases différentes"; exit 1; }
}

install_env(){
  log "== INSTALL ENV =="
  ask_pass

  if [[ -f "$CONTAINER" ]]; then
    if whiptail --yesno "Le conteneur existe. Écraser ?" 8 50; then
      rm -f "$CONTAINER"
      log "[OK] Ancien conteneur supprimé"
    else
      return
    fi
  fi

  cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
  if command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none \
      | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    dd if=/dev/zero bs=1M count="$cnt" >"$CONTAINER"
    log "[!pv] pas de barre"
  fi
  chmod 600 "$CONTAINER"; log "[OK] Fichier $SIZE"

  printf '%s' "$PASS" \
    | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  log "[OK] LUKS formaté"

  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  log "[OK] LUKS ouvert"

  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  log "[OK] ext4 formaté"

  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"
  log "[OK] Monté sur $MOUNT"

  show_summary
}

open_env(){
  log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] Pas de conteneur"; show_summary; return; }
  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -s -p "Passphrase LUKS : " PASS; echo
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  fi
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  log "[OK] Monté sur $MOUNT"
  show_summary
}

close_env(){
  log "== CLOSE ENV =="
  umount "$MOUNT" &>/dev/null && log "[OK] Démonté"
  cryptsetup close "$MAPPER" && log "[OK] LUKS fermé"
  show_summary
}

delete_env(){
  log "== DELETE ENV =="
  umount "$MOUNT" &>/dev/null||:
  cryptsetup close "$MAPPER" &>/dev/null||:
  rm -f "$CONTAINER" && log "[OK] Conteneur supprimé"
  rmdir "$MOUNT" 2>/dev/null||:
  show_summary
}

backup_env(){
  log "== BACKUP ENV =="
  ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_$ts.header"
  log "[OK] Backup créé"
  show_summary
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  show_summary
}

# ─── SSH avancé (Partie III) ──────────────────────────────────────────────
ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; log "[ER] Pas de ssh/config"; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && { whiptail --msgbox "Aucun Host" 6 50; log "[ER] Aucun host"; return; }
  CH=$(whiptail --title "ssh-create-template" \
    --menu "Choisissez host" 15 50 6 \
    "$(printf "%s\n" "${hosts[@]/#//}")" 3>&1 1>&2 2>&3) || return
  awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  log "[OK] Template $CH"
  whiptail --msgbox "Template '$CH' créé." 6 50
}

ssh_import_host(){ ssh_create_template; }

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  ln -sf "$ALIAS_LINK" "$USER_HOME/.aliases_env"
  log "[OK] Alias evsh"
  whiptail --msgbox "Alias 'evsh' prêt." 6 50
}

ssh_start(){
  log "== SSH START =="
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  [[ ${#cfgs[@]} -eq 0 ]] && { whiptail --msgbox "Aucune config SSH" 6 50; log "[ER] Pas de conf"; return; }
  tags=(); items=()
  for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" "" ); done
  CH=$(whiptail --title "ssh-start" \
    --menu "Choisissez conf" 15 60 ${#cfgs[@]} \
    "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$CH"
  log "[OK] SSH terminé"
}

ssh_delete(){
  log "== SSH DELETE =="
  rm -rf "$SSH_DIR"/*
  log "[OK] SSH vault vidé"
  whiptail --msgbox "Vault SSH vidé." 6 50
}

ssh_backup(){
  log "== SSH BACKUP =="
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  log "[OK] SSH backup $ts"
  whiptail --msgbox "Backup SSH ➜ ssh_wallet_$ts.tar.gz" 6 60
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  [[ ${#bs[@]} -eq 0 ]] && { whiptail --msgbox "Aucune sauvegarde" 6 50; log "[ER] Pas de backup"; return; }
  CH=$(whiptail --title "restore-ssh-wallet" \
    --menu "Choisissez backup" 15 60 ${#bs[@]} \
    "$(printf "%s\n" "${bs[@]/#//}")" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  log "[OK] Restauré $CH"
  whiptail --msgbox "Restauration terminée." 6 50
}

auto_open_toggle(){
  log "== AUTO-OPEN =="
  if [[ -f "$AUTO_FLAG" ]]; then
    sed -i "\|script2.sh open_env|d" "$USER_HOME/.bashrc"
    rm -f "$AUTO_FLAG"
    log "[OK] Auto-open OFF"
    whiptail --msgbox "Auto-open désactivé." 6 50
  else
    echo "$PWD/script2.sh open_env" >>"$USER_HOME/.bashrc"
    touch "$AUTO_FLAG"
    log "[OK] Auto-open ON"
    whiptail --msgbox "Auto-open activé." 6 50
  fi
}

# ─── Menu principal ──────────────────────────────────────────────────────
if [[ "${1:-}" == "--menu" ]]; then
  while :; do
    SECTION=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      Env "Environnement" \
      GPG "Cryptographie" \
      SSH "Configuration SSH" \
      Quit "Quitter" 3>&1 1>&2 2>&3) || exit
    case $SECTION in
      Env)
        ACTION=$(whiptail --title "Environnement" --menu "Choisissez" 20 60 6 \
          install_env "Installer" \
          open_env    "Ouvrir"    \
          close_env   "Fermer"    \
          delete_env  "Supprimer" \
          backup_env  "Backup"    \
          status_env  "Statut"    3>&1 1>&2 2>&3)
        $ACTION
        ;;
      GPG)
        ACTION=$(whiptail --title "GPG" --menu "Choisissez" 15 60 2 \
          gpg_setup  "Setup" \
          gpg_import "Import" 3>&1 1>&2 2>&3)
        $ACTION
        ;;
      SSH)
        ACTION=$(whiptail --title "SSH" --menu "Choisissez" 25 60 8 \
          ssh_create_template "ssh-create-template" \
          ssh_import_host     "ssh-import-host"     \
          ssh_setup_alias     "ssh-setup-alias"     \
          ssh_start           "ssh-start"           \
          ssh_delete          "ssh-delete"          \
          ssh_backup          "ssh-backup"          \
          restore_ssh_wallet  "restore-ssh-wallet"  \
          auto_open_toggle    "auto-open"           3>&1 1>&2 2>&3)
        $ACTION
        ;;
      Quit) exit 0 ;;
    esac
  done
else
  echo "Usage : $0 --menu"
fi
