#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail
set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

#  Couleurs & log 
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi
LOG="$USER_HOME/secure_env.log"; : >"$LOG"
exec 3>&1
log()    { echo "[$(date +%T)] $*" >>"$LOG"; }
info()   { echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }
error()  { echo -e "${RED}$*${NC}" >&2; }

#  Pré-vérifications 
(( EUID==0 )) || { error "[X] Relancez en root !"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv \
           whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "[X] $cmd manquant"; exit 1; }
done

# Variables globales 
DEFAULT_SIZE="5G"
CONTAINER="$USER_HOME/env.img"
MAPPER="env_sec"
MOUNT="$USER_HOME/env_mount"
BACKUP="$USER_HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
SSH_CONFIG_PATH="$SSH_DIR/ssh_config"
SSH_ALIAS_FILE="$SSH_DIR/ssh_aliases"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"
INTERACTIVE=0

mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"; sleep .1
  done
  printf "\r"
}

show_summary(){
  local msg="${1:-}"
  if [[ "$INTERACTIVE" -eq 1 ]]; then
    whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
    [[ -n "$msg" ]] && whiptail --msgbox "$msg" 8 50
  fi
  echo -e "\n— Derniers logs —" >&3
  tail -n 10 "$LOG" >&3
  [[ -n "$msg" ]] && echo "$msg" >&3
}

cleanup_stale(){
  if mountpoint -q "$MOUNT"; then
    umount "$MOUNT" && log "[OK] point de montage nettoyé"
  fi
  if cryptsetup status "$MAPPER" &>/dev/null; then
    cryptsetup close "$MAPPER" && log "[OK] mapper fermé"
  fi
}

ensure_env_open(){
  if ! mountpoint -q "$MOUNT"; then
    open_env || return 1
  fi
}

# PART I & IV : LUKS/ext4 
ask_pass(){
  read -p "Taille du conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "[X] Passphrases différentes"; exit 1; }
}

install_env(){
  cleanup_stale; log "== INSTALL ENV =="
  ask_pass
  if [[ -f "$CONTAINER" ]]; then
    if whiptail --yesno "Le conteneur existe. Écraser ?" 8 50; then
      rm -f "$CONTAINER"; log "[OK] Ancien conteneur supprimé"
    else
      return
    fi
  fi
  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création du fichier ($SIZE)…"
  if command -v fallocate &>/dev/null; then
    fallocate -l "$SIZE" "$CONTAINER" & spinner $!
  elif command -v pv &>/dev/null; then
    ( dd if=/dev/zero bs=1M count="$cnt" \
        | pv -s $((cnt*1024*1024)) >"$CONTAINER" ) & spinner $!
  else
    dd if=/dev/zero bs=1M count="$cnt" of="$CONTAINER" & spinner $!
    log "[!pv] pas de progression"
  fi
  chmod 600 "$CONTAINER"; log "[OK] conteneur créé"

  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  log "[OK] LUKS formaté"

  info "Ouverture LUKS…"
  printf '%s' "$PASS" \
    | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  log "[OK] /dev/mapper/$MAPPER"

  info "Formatage ext4…"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  log "[OK] ext4 formaté"

  info "Montage…"
  mount "/dev/mapper/$MAPPER" "$MOUNT" && chmod -R go-rwx "$MOUNT"
  log "[OK] Monté sur $MOUNT"

  local msg="✅ Install & mount OK"
  success "$msg"; show_summary "$msg"
}

# ─── OPEN_ENV CORRIGÉ ────────────────────────────────────────────────────────
open_env(){
  log "== OPEN ENV =="
  # 1) LUKS
  if cryptsetup status "$MAPPER" &>/dev/null; then
    info  "⚠️ LUKS déjà ouvert"
    log   "[!!] LUKS déjà ouvert"
  else
    [[ -f "$CONTAINER" ]] || { log "[ER] conteneur manquant"; show_summary "[X] Conteneur manquant"; return; }
    read -s -p "Passphrase LUKS : " PASS; echo
    info "Ouverture LUKS…"
    printf '%s' "$PASS" \
      | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  fi

  # 2) Montage
  if mountpoint -q "$MOUNT"; then
    info  "⚠️ Déjà monté sur $MOUNT"
    log   "[!!] Déjà monté"
  else
    mount "/dev/mapper/$MAPPER" "$MOUNT"
    chmod -R go-rwx "$MOUNT"
    log "[OK] Monté sur $MOUNT"
  fi

  local msg="✅ Environment ouvert et monté"
  success "$msg"; show_summary "$msg"
}

# CLOSE_ENV  
close_env(){
  log "== CLOSE ENV =="
  if mountpoint -q "$MOUNT"; then
    umount "$MOUNT" && log "[OK] point de montage démonté"
  else
    info  "⚠️ Pas monté"
    log   "[!!] Pas monté"
  fi
  if cryptsetup status "$MAPPER" &>/dev/null; then
    cryptsetup close "$MAPPER" && log "[OK] LUKS fermé"
  else
    info  "⚠️ Mapper déjà fermé"
    log   "[!!] Mapper déjà fermé"
  fi
  local msg="✅ Environment fermé"
  success "$msg"; show_summary "$msg"
}

#  DELETE_ENV CORRIGÉ 
delete_env(){
  log "== DELETE ENV =="
  close_env
  if [[ -f "$CONTAINER" ]]; then
    rm -f "$CONTAINER" && log "[OK] conteneur supprimé"
  else
    log "[!!] Pas de conteneur à supprimer"
  fi
  rmdir "$MOUNT" 2>/dev/null || :
  local msg="✅ Environment supprimé"
  success "$msg"; show_summary "$msg"
}

backup_env(){
  log "== BACKUP ENV =="
  local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"
  log "[OK] Backup env+header"
  local msg="✅ Backup créé dans $BACKUP"
  success "$msg"; show_summary "$msg"
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>/dev/null || echo "mapper fermé" >>"$LOG"
  local msg="✅ Statut enregistré"
  success "$msg"; show_summary "$msg"
}

# GPG 
gpg_setup(){
  log "== GPG SETUP =="
  ensure_env_open || return
  mkdir -p "$GPG_DIR"
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
  local key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
  log "[OK] pub → $GPG_DIR/public_${key}.gpg"
  if whiptail --yesno "Exporter la clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
    log "[OK] priv → $GPG_DIR/private_${key}.gpg"
  fi
  local msg="✅ GPG setup terminé (public+priv dans $GPG_DIR)"
  success "$msg"; show_summary "$msg"
}

gpg_import(){
  log "== GPG IMPORT =="
  ensure_env_open || return
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] import $f"
  done
  shopt -u nullglob
  local msg="✅ Import GPG terminé"
  success "$msg"; show_summary "$msg"
}

gpg_export(){
  log "== GPG EXPORT =="
  ensure_env_open || return
  mkdir -p "$GPG_DIR"
  mapfile -t keys < <(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}')
  (( ${#keys[@]} )) || { whiptail --msgbox "Aucune clé à exporter" 8 50; return; }
  for k in "${keys[@]}"; do
    gpg --export --armor "$k" >"$GPG_DIR/public_${k}.gpg"
    gpg --export-secret-keys --armor "$k" >"$GPG_DIR/private_${k}.gpg"
    chmod 600 "$GPG_DIR/private_${k}.gpg"
    log "[OK] export $k"
  done
  local msg="✅ Export GPG terminé"
  success "$msg"; show_summary "$msg"
}

# SSH avancé
ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  ensure_env_open || return

  if [[ ! -f "$SSH_CONFIG" ]]; then
    if whiptail --yesno "Aucune config SSH. Créer un host test ?" 8 60; then
      mkdir -p "$(dirname "$SSH_CONFIG")"
      ssh-keygen -t rsa -b 2048 -f "$USER_HOME/.ssh/id_rsa_test" -N "" -C "test-host"
      cat >>"$SSH_CONFIG" <<EOF
Host test-host
  HostName localhost
  User ${SUDO_USER:-$(whoami)}
  IdentityFile $USER_HOME/.ssh/id_rsa_test
EOF
      chmod 600 "$SSH_CONFIG"
      log "[OK] Host test 'test-host' créé"
      success "✅ Host test ajouté à $SSH_CONFIG"
    else
      whiptail --msgbox "Impossible sans config SSH." 8 50
      log "[ER] Pas de config SSH"
      return
    fi
  fi

  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun Host valide." 6 50; log "[ER] Aucun Host"; return; }

  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --title "ssh-create-template" \
    --menu "Choisissez un host :" 15 60 ${#hosts[@]} \
    "${tags[@]}" 3>&1 1>&2 2>&3) || return

  awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_CONFIG_PATH"
  idf=$(awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2;exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")"
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_CONFIG_PATH"
  fi

  log "[OK] Template sshconf_$CH créé"
  whiptail --msgbox "✅ Template '$CH' → $SSH_DIR/sshconf_$CH" 8 60
}

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  ensure_env_open || return
  echo "alias evsh='ssh -F $SSH_CONFIG_PATH'" >"$SSH_ALIAS_FILE"
  chmod 644 "$SSH_ALIAS_FILE"
  ln -sf "$SSH_ALIAS_FILE" "$ALIAS_LINK"
  log "[OK] alias evsh dans $SSH_ALIAS_FILE (lien $ALIAS_LINK)"
  local msg="✅ Alias prêt (source $ALIAS_LINK)"
  success "$msg"; show_summary "$msg"
}

ssh_import_host(){
  log "== SSH IMPORT HOST =="
  ensure_env_open || return
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de $SSH_CONFIG" 6 50; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun host" 6 50; return; }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez host" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  block=$(awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG")
  [[ -n "$block" ]] || { whiptail --msgbox "Bloc introuvable" 6 50; return; }

  if grep -q "^Host $CH$" "$SSH_CONFIG_PATH" 2>/dev/null; then
    whiptail --yesno "Host $CH existe déjà. Remplacer ?" 8 60 || return
    awk -v h="$CH" 'BEGIN{p=1} /^Host /{if($2==h){p=0;next}; if(!p){p=1;next}} {print}' "$SSH_CONFIG_PATH" >"$SSH_CONFIG_PATH.tmp"
    mv "$SSH_CONFIG_PATH.tmp" "$SSH_CONFIG_PATH"
  fi

  printf '%s\n' "$block" >>"$SSH_CONFIG_PATH"

  while read -r line; do
    if [[ $line =~ [Ii]dentity[Ff]ile[[:space:]]+(.+) ]]; then
      idf=${BASH_REMATCH[1]}
      base=$(basename "$idf")
      cp "$idf" "$SSH_DIR/$base" && chmod 600 "$SSH_DIR/$base"
      [[ -f "${idf}.pub" ]] && cp "${idf}.pub" "$SSH_DIR/${base}.pub"
      sed -i "s|$idf|$SSH_DIR/$base|g" "$SSH_CONFIG_PATH"
    fi
  done <<<"$block"

  log "[OK] Host $CH importé"
  local msg="✅ SSH host importé → $SSH_CONFIG_PATH"
  success "$msg"; show_summary "$msg"
}

ssh_delete(){
  log "== SSH DELETE =="
  ensure_env_open || return
  rm -rf "$SSH_DIR"/*
  whiptail --msgbox "Vault SSH vidé" 6 50; log "[OK] Vault vidé"
  local msg="✅ Vault SSH vidé"
  success "$msg"; show_summary "$msg"
}

ssh_backup(){
  log "== SSH BACKUP =="
  ensure_env_open || return
  local ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  whiptail --msgbox "Backup → $SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" 6 60
  log "[OK] backup $ts créé"
  local msg="✅ SSH backup créé"
  success "$msg"; show_summary "$msg"
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  ensure_env_open || return
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  (( ${#bs[@]} )) || { whiptail --msgbox "Pas de backup SSH" 6 50; return; }
  tags=(); for b in "${bs[@]}"; do tags+=( "$(basename "$b")" "" ); done
  CH=$(whiptail --menu "Choisissez backup" 15 60 ${#bs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  whiptail --msgbox "Backup restauré → $CH" 6 60; log "[OK] restauré $CH"
  local msg="✅ SSH wallet restauré"
  success "$msg"; show_summary "$msg"
}

auto_open_toggle(){
  log "== AUTO-OPEN TOGGLE =="
  if grep -q "secure_env.sh open_env" "$USER_HOME/.bashrc"; then
    sed -i "/secure_env.sh open_env/d" "$USER_HOME/.bashrc"
    log "[OK] Auto-open OFF"; success "✅ Auto-open désactivé"
  else
    echo "$PWD/secure_env.sh open_env &>/dev/null" >>"$USER_HOME/.bashrc"
    log "[OK] Auto-open ON"; success "✅ Auto-open activé"
  fi
  show_summary
}

# Menu principal & mode direct
cleanup_stale

if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1
  while true; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      Environnement  "LUKS/ext4" \
      Cryptographie  "GPG"     \
      SSH            "SSH"     \
      Quitter        "Quitter" 3>&1 1>&2 2>&3) || exit 0
    case $CH in
      Environnement)
        ACTION=$(whiptail --title "Environnement" --menu "Choisissez" 20 60 6 \
          install_env "Installer" \
          open_env    "Ouvrir"    \
          close_env   "Fermer"    \
          delete_env  "Supprimer" \
          backup_env  "Backup"    \
          status_env  "Statut"    3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      Cryptographie)
        ACTION=$(whiptail --title "GPG" --menu "Choisissez" 15 60 3 \
          gpg_setup  "Setup" \
          gpg_import "Import" \
          gpg_export "Export" 3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      SSH)
        ACTION=$(whiptail --title "SSH" --menu "Choisissez" 20 60 6 \
          ssh_create_template "ssh-create-template" \
          ssh_setup_alias     "ssh-setup-alias"     \
          ssh_import_host     "ssh-import-host"     \
          ssh_delete          "ssh-delete"          \
          ssh_backup          "ssh-backup"          \
          restore_ssh_wallet  "restore-ssh-wallet"  \
          auto_open_toggle    "auto-open"           3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      Quitter) exit 0 ;;
    esac
  done
else
  ACTION="${1//-/_}"
  if [[ -n "$ACTION" && $(type -t "$ACTION") == "function" ]]; then
        shift
    "$ACTION" "$@"
  else
    echo "Usage: $0 --menu | <action>" >&2
    exit 1
  fi
fi
