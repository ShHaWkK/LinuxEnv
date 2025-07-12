#!/bin/bash
# Author : ShHawk alias Alexandre Uzan
# Sujet  : Coffre Sécurisé complet (LUKS, ext4, GPG, SSH, menu interactif)

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ───────────────────────────────────────────────────────────────────────────────
# Couleurs & utils
# ───────────────────────────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
info()    { echo -e "${BLUE}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }
log()     { echo "$*" >>"$LOG"; }

# ───────────────────────────────────────────────────────────────────────────────
# Pré-vérifications
# ───────────────────────────────────────────────────────────────────────────────
(( EUID==0 )) || { error "Relancez en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate lsblk df blkid pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "$cmd manquant"; exit 1; }
done

# ───────────────────────────────────────────────────────────────────────────────
# Variables globales
# ───────────────────────────────────────────────────────────────────────────────
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

# Crée les dossiers nécessaires
mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

# ───────────────────────────────────────────────────────────────────────────────
# Spinner pour longues opérations
# ───────────────────────────────────────────────────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

# ───────────────────────────────────────────────────────────────────────────────
# Affiche le log final dans une boîte
# ───────────────────────────────────────────────────────────────────────────────
show_summary(){
  whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
}

# ───────────────────────────────────────────────────────────────────────────────
# Lecture passphrase & options
# ───────────────────────────────────────────────────────────────────────────────
ask_pass(){
  read -p "Taille conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Passphrases différentes"; exit 1; }
  read -s -p "Exporter clé privée GPG ? [y/N] : " EXP_PRIV; echo
}

# ───────────────────────────────────────────────────────────────────────────────
# Partie I & IV : Environnement LUKS/ext4
# ───────────────────────────────────────────────────────────────────────────────
install_env(){
  log "== INSTALL ENV =="
  ask_pass

  # écrasement éventuel
  if [[ -f "$CONTAINER" ]]; then
    if whiptail --yesno "Le conteneur existe déjà. Écraser ?" 8 50; then
      rm -f "$CONTAINER"
      log "[OK] Ancien conteneur supprimé"
    else
      return
    fi
  fi

  # 1) création du fichier
  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  if command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none \
      | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    dd if=/dev/zero bs=1M count="$cnt" >"$CONTAINER"
    log "[!pv] pas de barre de progression"
  fi
  chmod 600 "$CONTAINER"
  log "[OK] Fichier conteneur créé ($SIZE)"

  # 2) format LUKS batch
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  cryptsetup isLuks "$CONTAINER" && log "[OK] LUKS formaté" || log "[ER] LUKS format failed"

  # 3) open LUKS
  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  [[ -e "/dev/mapper/$MAPPER" ]] && log "[OK] LUKS ouvert" || log "[ER] LUKS open failed"

  # 4) format ext4
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  blkid "/dev/mapper/$MAPPER" &>/dev/null && log "[OK] ext4 formaté" || log "[ER] ext4 failed"

  # 5) montage
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"
  mountpoint -q "$MOUNT" && log "[OK] Monté sur $MOUNT" || log "[ER] mount failed"

  show_summary
}

open_env(){
  log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] Conteneur manquant"; show_summary; return; }
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
  local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_$ts.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_$ts.header"
  log "[OK] Backup env & header créés"
  show_summary
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  show_summary
}

# ───────────────────────────────────────────────────────────────────────────────
# Partie II : Cryptographie GPG
# ───────────────────────────────────────────────────────────────────────────────
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
  gpg --batch --generate-key gpg-batch; rm -f gpg-batch
  local key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key"       >"$GPG_DIR/public_$key.gpg"
  log "[OK] Public GPG exporté"
  if whiptail --yesno "Exporter privé ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_$key.gpg"
    chmod 600 "$GPG_DIR/private_$key.gpg"
    log "[OK] Privé GPG exporté"
  fi
  show_summary
}

gpg_import(){
  log "== GPG IMPORT =="
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f"
    log "[OK] Import $f"
  done
  show_summary
}

# ───────────────────────────────────────────────────────────────────────────────
# Partie III : Configuration SSH avancée
# ───────────────────────────────────────────────────────────────────────────────
ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  [[ ! -f "$SSH_CONFIG" ]] && {
    whiptail --msgbox "Aucun ~/.ssh/config" 6 50
    log "[ER] ~/.ssh/config introuvable"
    return
  }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && {
    whiptail --msgbox "Aucun host dans $SSH_CONFIG" 6 50
    log "[ER] Aucun host"
    return
  }
  CH=$(whiptail --title "ssh-create-template" \
    --menu "Choisissez Host" 15 50 6 \
    "$(printf "%s\n" "${hosts[@]/#//}")" 3>&1 1>&2 2>&3) || return
  awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  log "[OK] Config template pour $CH"
  whiptail --msgbox "Template sshconf_$CH créé." 6 50
}

ssh_import_host(){
  log "== SSH IMPORT HOST =="
  ssh_create_template
}

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  ln -sf "$ALIAS_LINK" "$USER_HOME/.aliases_env"
  whiptail --msgbox "Alias evsh prêt (source ~/.aliases_env)." 6 50
  log "[OK] Alias evsh créé"
}

ssh_start(){
  log "== SSH START =="
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  [[ ${#cfgs[@]} -eq 0 ]] && {
    whiptail --msgbox "Aucun sshconf_* trouvé" 6 50
    log "[ER] Aucune conf SSH"
    return
  }
  tags=(); for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" "" ); done
  CH=$(whiptail --title "ssh-start" \
    --menu "Choisissez config SSH" 15 60 ${#cfgs[@]} \
    "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$CH"
  log "[OK] SSH session avec $CH terminée"
}

ssh_delete(){
  log "== SSH DELETE =="
  rm -rf "$SSH_DIR"/*
  whiptail --msgbox "Vault SSH vidé." 6 50
  log "[OK] SSH vault vidé"
}

ssh_backup(){
  log "== SSH BACKUP =="
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  whiptail --msgbox "Backup SSH ➜ ssh_wallet_$ts.tar.gz" 6 60
  log "[OK] SSH backup créé"
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null | xargs -n1 basename)
  [[ ${#bs[@]} -eq 0 ]] && {
    whiptail --msgbox "Aucune sauvegarde SSH" 6 50
    log "[ER] Pas de SSH backup"
    return
  }
  CH=$(whiptail --title "restore-ssh-wallet" \
    --menu "Choisissez backup" 15 60 ${#bs[@]} \
    "$(printf "%s\n" "${bs[@]/#//}")" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  whiptail --msgbox "SSH wallet restauré." 6 50
  log "[OK] Restauré $CH"
}

auto_open_toggle(){
  log "== AUTO-OPEN =="
  if [[ -f "$AUTO_FLAG" ]]; then
    sed -i "\|script2.sh open_env|d" "$USER_HOME/.bashrc"
    rm -f "$AUTO_FLAG"
    whiptail --msgbox "Auto-open désactivé." 6 50
    log "[OK] Auto-open off"
  else
    echo "$PWD/script2.sh open_env" >>"$USER_HOME/.bashrc"
    touch "$AUTO_FLAG"
    whiptail --msgbox "Auto-open activé." 6 50
    log "[OK] Auto-open on"
  fi
}

# ───────────────────────────────────────────────────────────────────────────────
# Menu principal
# ───────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--menu" ]]; then
  while :; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      1 "Environ­nement" 2 "GPG" 3 "SSH" 4 "Quitter" \
      3>&1 1>&2 2>&3) || exit
    case $CH in
      1)
        OP=( install_env "Installer" \
             open_env    "Ouvrir"    \
             close_env   "Fermer"    \
             delete_env  "Supprimer" \
             backup_env  "Backup"    \
             status_env  "Statut" )
        SEL=$(whiptail --menu "Environnement" 20 60 ${#OP[@]}/2 "${OP[@]}" 3>&1 1>&2 2>&3)
        $SEL ;;
      2)
        SEL=$(whiptail --menu "GPG" 15 60 2 \
              gpg_setup  "Setup" \
              gpg_import "Import" \
              3>&1 1>&2 2>&3)
        $SEL ;;
      3)
        ssh_create_template    # pour s’assurer d’avoir toujours un template
        ssh_section_fn=( ssh_create_template  "create-template" \
                         ssh_import_host      "import-host"    \
                         ssh_setup_alias      "setup-alias"    \
                         ssh_start            "start"          \
                         ssh_delete           "delete"         \
                         ssh_backup           "backup"         \
                         restore_ssh_wallet   "restore"        \
                         auto_open_toggle     "auto-open" )
        SEL=$(whiptail --menu "SSH" 25 60 ${#ssh_section_fn[@]}/2 "${ssh_section_fn[@]}" 3>&1 1>&2 2>&3)
        $SEL ;;
      4) exit 0 ;;
    esac
  done
else
  echo "Usage : $0 --menu"
fi
