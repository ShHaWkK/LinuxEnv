#!/usr/bin/env bash
##############################################################################
# secure_env.sh — Coffre LUKS/ext4 + GPG + SSH (menu ou CLI)
# Journal : $HOME/secure_env.log   •   Auteur : OpenAI 2025-07
##############################################################################
set -Eeuo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

##############################################################################
# Couleurs & journal
##############################################################################
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'

# Détermine $USER_HOME même sous sudo
[[ -n ${SUDO_USER-} && $SUDO_USER != root ]] &&
  USER_HOME="/home/$SUDO_USER" || USER_HOME="$HOME"

LOG="$USER_HOME/secure_env.log"; : >"$LOG"
exec 3>&1
trap 'error "⛔ Erreur ligne $LINENO – consultez $LOG"; exit 1' ERR

log()     { echo "[$(date +%T)] $*" >>"$LOG"; }
info()    { echo -e "${BLUE}$*${NC}"  >&3;   log "$*"; }
success() { echo -e "${GREEN}$*${NC}" >&3;   log "$*"; }
error()   { echo -e "${RED}$*${NC}"   >&2;   log "ERREUR : $*"; }

##############################################################################
# Vérifications de dépendances
##############################################################################
(( EUID == 0 )) || { error "Exécuter en root (sudo)"; exit 1; }

must_have=(cryptsetup mkfs.ext4 mount umount fallocate dd lsblk df \
           losetup gpg ssh-keygen ssh-copy-id tar chattr)
opt_have=(pv whiptail)

for b in "${must_have[@]}"; do
  command -v "$b" &>/dev/null || { error "$b manquant"; exit 1; }
done
for b in "${opt_have[@]}"; do
  command -v "$b" &>/dev/null || info "⚠️  $b non installé – fonctionnalités réduites"
done

##############################################################################
# Variables globales
##############################################################################
DEFAULT_SIZE="5G"

CONTAINER="$USER_HOME/env.img"
MAPPER="env_sec"
MOUNT="$USER_HOME/env_mount"
BACKUP="$USER_HOME/env_backups"

# --- SSH
SSH_DIR="$MOUNT/ssh"
SSH_TEMPLATES_DIR="$SSH_DIR/conf"
SSH_KEYS_DIR="$SSH_DIR/keys"
ALIAS_FILE_IN_VAULT="$SSH_DIR/aliases_env"
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"

# --- GPG
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"

DEFAULT_KEY_TYPE="ed25519"
INTERACTIVE=0

mkdir -p "$MOUNT" "$BACKUP" "$SSH_TEMPLATES_DIR" "$SSH_KEYS_DIR" \
         "$GPG_DIR" "$SSH_BACKUP_DIR"

##############################################################################
# Fonctions utilitaires
##############################################################################
spinner() {                       # Affiche un petit spinner si pv présent
  command -v pv &>/dev/null || return
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%4:1}"; sleep .1
  done
  printf "\r"
}

show_summary() {                  # Affiche résumé + messages
  local msg="${1:-}"
  if (( INTERACTIVE )) && command -v whiptail &>/dev/null; then
    whiptail --title "Résumé" --textbox "$LOG" 20 70
    [[ -n $msg ]] && whiptail --msgbox "$msg" 8 60
  fi
  tail -n 8 "$LOG" >&3
  [[ -n $msg ]] && info "$msg"
}

cleanup_stale() {                 # Ferme LUKS / démonte si précédent crash
  mountpoint -q "$MOUNT"  && umount "$MOUNT" && log "[OK] démonté"
  cryptsetup status "$MAPPER" &>/dev/null \
    && cryptsetup close "$MAPPER" && log "[OK] LUKS fermé"
}

ensure_env_open() { mountpoint -q "$MOUNT" || open_env; }

tight_perms() {                   # Verrouille permissions
  chmod 700 "$SSH_DIR" "$SSH_TEMPLATES_DIR" "$SSH_KEYS_DIR" "$GPG_DIR"
  chmod 600 "$CONTAINER" || true
}

##############################################################################
# PART I / IV – LUKS + ext4
##############################################################################
ask_pass() {
  read -rp "Taille (ex : 5G) [${DEFAULT_SIZE}] : " SIZE; SIZE=${SIZE:-$DEFAULT_SIZE}
  read -rsp "Passphrase : " PASS;  echo
  read -rsp "Confirmer  : " PASS2; echo
  [[ $PASS == "$PASS2" ]] || { error "Passphrases différentes"; exit 1; }
}

install_env() {
  cleanup_stale; log "== INSTALL =="; ask_pass

  [[ -f $CONTAINER ]] && { rm -f "$CONTAINER"; log "Ancien conteneur supprimé"; }

  local cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création conteneur $SIZE…"
  if fallocate -l "$SIZE" "$CONTAINER" 2>/dev/null; then :
  else
    (dd if=/dev/zero bs=1M count="$cnt" | pv -s $((cnt*1024*1024)) >"$CONTAINER") &
    spinner $!
  fi
  chmod 600 "$CONTAINER"

  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=-

  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  mkfs.ext4 -q "/dev/mapper/$MAPPER"
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod go-rwx "$MOUNT"

  chattr +i "$CONTAINER" 2>/dev/null || true
  tight_perms
  success "Coffre installé et monté"
  show_summary
}

open_env() {
  log "== OPEN =="; [[ -f $CONTAINER ]] || { error "Conteneur absent"; return; }

  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -rsp "Passphrase : " PASS; echo
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  else
    info "LUKS déjà ouvert"
  fi

  mountpoint -q "$MOUNT" || { mount "/dev/mapper/$MAPPER" "$MOUNT"; chmod go-rwx "$MOUNT"; }
  tight_perms
  success "Coffre ouvert"; show_summary
}

close_env() {
  log "== CLOSE =="; mountpoint -q "$MOUNT" && umount "$MOUNT"
  cryptsetup status "$MAPPER" &>/dev/null && cryptsetup close "$MAPPER"
  success "Coffre fermé"; show_summary
}

delete_env() {
  close_env; rm -f "$CONTAINER"; rmdir "$MOUNT" 2>/dev/null || :
  success "Coffre supprimé"; show_summary
}

backup_env() {
  ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.hdr"
  success "Backup LUKS → $BACKUP/env_${ts}.img"; show_summary
}

status_env() {
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -hT | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>/dev/null || echo "mapper fermé" >>"$LOG"
  success "Statut dans $LOG"; show_summary
}

##############################################################################
# PART II – GPG
##############################################################################
gpg_setup() {
  ensure_env_open; log "== GPG SETUP =="

  read -rp "Nom        : " N
  read -rp "Email      : " E
  read -rp "Commentaire: " C

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
  gpg --batch --generate-key gpg-batch && rm gpg-batch

  key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.asc"

  if command -v whiptail &>/dev/null && \
     whiptail --yesno "Sauvegarder aussi la clé privée ?" 8 60; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.asc"
    chmod 600 "$GPG_DIR/private_${key}.asc"
  fi

  success "Clé GPG $key générée"; show_summary
}

gpg_import() {
  ensure_env_open; shopt -s nullglob
  for f in "$GPG_DIR"/*.asc; do gpg --import "$f"; done
  shopt -u nullglob
  success "Import GPG terminé"; show_summary
}

##############################################################################
# PART III – SSH
##############################################################################
rewrite_identity() {               # copie clés & ré-écrit IdentityFile
  local tpl="$1"
  awk '/IdentityFile/ {print $2}' "$tpl" | while read -r idf; do
    for f in "$idf" "$idf.pub"; do
      [[ -f $f ]] && cp "$f" "$SSH_KEYS_DIR/" && chmod 600 "$SSH_KEYS_DIR/$(basename "$f")"
    done
    sed -i "s|$idf|$SSH_KEYS_DIR/$(basename "$idf")|g" "$tpl"
  done
  chmod 600 "$tpl"
}

ssh_create_template() {
  ensure_env_open; [[ -f $SSH_CONFIG ]] || { error "$SSH_CONFIG absent"; return; }

  mapfile -t hosts < <(grep -E '^Host[[:space:]]+' "$SSH_CONFIG" | awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && { error "Aucun Host"; return; }

  local CH
  if command -v whiptail &>/dev/null; then
    tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
    CH=$(whiptail --menu "Choisissez un Host" 20 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  else
    printf 'Hosts :\n'; printf ' - %s\n' "${hosts[@]}"; read -rp "Choix : " CH
  fi

  tpl="$SSH_TEMPLATES_DIR/${CH}.conf"
  awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" "$SSH_CONFIG" >"$tpl"
  rewrite_identity "$tpl"
  success "Template $tpl créé"; show_summary
}

ssh_import_hosts() {
  ensure_env_open; [[ -f $SSH_CONFIG ]] || { error "$SSH_CONFIG absent"; return; }

  mapfile -t hosts < <(grep -E '^Host[[:space:]]+' "$SSH_CONFIG" | awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && { error "Aucun Host"; return; }

  local list=("$@"); [[ ${#list[@]} -eq 0 ]] && list=("${hosts[@]}")

  for CH in "${list[@]}"; do
    tpl="$SSH_TEMPLATES_DIR/${CH}.conf"
    awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" "$SSH_CONFIG" >"$tpl"
    rewrite_identity "$tpl"
    log "Import $CH OK"
  done

  success "Import SSH terminé"; show_summary
}

ssh_add_host() {                   # création complète
  ensure_env_open
  local HOST_ALIAS HOST_NAME HOST_USER HOST_PORT KEYTYPE BITS

  if (( $# >= 4 )); then
    HOST_ALIAS=$1; HOST_NAME=$2; HOST_USER=$3; HOST_PORT=$4
    KEYTYPE=${5:-$DEFAULT_KEY_TYPE}; BITS=${6:-}
  else
    read -rp "Alias (Host) : " HOST_ALIAS
    [[ -z $HOST_ALIAS ]] && { error "Alias vide"; return; }
    read -rp "HostName (IP/FQDN) : " HOST_NAME
    read -rp "User [ubuntu]      : " HOST_USER; HOST_USER=${HOST_USER:-ubuntu}
    read -rp "Port [22]          : " HOST_PORT; HOST_PORT=${HOST_PORT:-22}
    read -rp "Type clé [$DEFAULT_KEY_TYPE] : " KEYTYPE; KEYTYPE=${KEYTYPE:-$DEFAULT_KEY_TYPE}
    [[ $KEYTYPE == rsa ]] && read -rp "Bits [4096] : " BITS
  fi

  KEY_PATH="$SSH_KEYS_DIR/$HOST_ALIAS"
  [[ -e $KEY_PATH ]] && { error "Clé déjà existante"; return; }

  ssh-keygen -t "$KEYTYPE" ${BITS:+-b "$BITS"} -f "$KEY_PATH" -N "" -C "$HOST_ALIAS" &>/dev/null
  chmod 600 "$KEY_PATH" "$KEY_PATH.pub"

  cat >"$SSH_TEMPLATES_DIR/${HOST_ALIAS}.conf" <<EOF
Host $HOST_ALIAS
  HostName $HOST_NAME
  User $HOST_USER
  Port $HOST_PORT
  IdentityFile $KEY_PATH
  IdentitiesOnly yes
EOF
  chmod 600 "$SSH_TEMPLATES_DIR/${HOST_ALIAS}.conf"

  success "Host $HOST_ALIAS créé"; show_summary
}

ssh_choose_template() {
  ensure_env_open; mapfile -t tpls < <(basename -a "$SSH_TEMPLATES_DIR"/*.conf 2>/dev/null)
  [[ ${#tpls[@]} -eq 0 ]] && { error "Pas de template"; return; }

  local CH="$1"
  if [[ -z $CH ]]; then
    if command -v whiptail &>/dev/null; then
      tags=(); for t in "${tpls[@]}"; do tags+=( "$t" "" ); done
      CH=$(whiptail --menu "Template actif" 15 60 ${#tpls[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
    else
      printf 'Templates :\n'; printf ' - %s\n' "${tpls[@]}"; read -rp "Choix : " CH
    fi
  fi

  printf 'alias evsh="ssh -F %s %%@"\n' "$SSH_TEMPLATES_DIR/$CH" >"$ALIAS_FILE_IN_VAULT"
  chmod 600 "$ALIAS_FILE_IN_VAULT"
  ln -sf "$ALIAS_FILE_IN_VAULT" "$ALIAS_LINK"

  for rc in "$USER_HOME/.bashrc" "$USER_HOME/.zshrc"; do
    if [[ -f $rc ]] && ! grep -qF ".aliases_env" "$rc"; then
      echo "source ~/.aliases_env" >>"$rc"
    fi
  done

  success "Template $CH activé"; show_summary
}

ssh_delete()   { ensure_env_open; rm -rf "$SSH_DIR"/*; success "Vault SSH vidé"; }
ssh_backup()   { ensure_env_open; ts=$(date +%Y%m%d_%H%M%S); \
                 tar czf "$SSH_BACKUP_DIR/ssh_$ts.tar.gz" -C "$SSH_DIR" .; \
                 success "Backup SSH : $SSH_BACKUP_DIR/ssh_$ts.tar.gz"; }
restore_ssh_wallet() {
  ensure_env_open
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_*.tar.gz 2>/dev/null || :)
  [[ ${#bs[@]} -eq 0 ]] && { error "Pas de backup"; return; }
  local CH=${1:-${bs[-1]}}; rm -rf "$SSH_DIR"/*; tar xzf "$CH" -C "$SSH_DIR"
  success "Backup restauré : $(basename "$CH")"
}

auto_open_toggle() {
  local line="$PWD/secure_env.sh open_env &>/dev/null"
  if grep -qsF "$line" "$USER_HOME/.bashrc"; then
    sed -i "\|$line|d" "$USER_HOME/.bashrc"; success "Auto-open désactivé"
  else
    echo "$line" >>"$USER_HOME/.bashrc"; success "Auto-open activé"
  fi
}

##############################################################################
# Interface : menu (si whiptail) ou CLI
##############################################################################
cleanup_stale

if [[ ${1:-} == --menu && -x $(command -v whiptail) ]]; then
  INTERACTIVE=1
  while true; do
    ITEM=$(whiptail --title "Coffre sécurisé" --menu "Choisissez…" 20 68 15 \
      install_env "Installer le coffre" \
      open_env    "Ouvrir le coffre" \
      close_env   "Fermer le coffre" \
      delete_env  "Supprimer le coffre" \
      backup_env  "Backup LUKS" \
      status_env  "Statut LUKS" \
      gpg_setup   "Créer une clé GPG" \
      gpg_import  "Importer clés GPG" \
      ssh_add_host        "Créer un Host SSH" \
      ssh_create_template "Template depuis ~/.ssh/config" \
      ssh_import_hosts    "Importer Hosts (.ssh/config)" \
      ssh_choose_template "Activer template & alias" \
      ssh_backup          "Backup vault SSH" \
      restore_ssh_wallet  "Restaurer backup SSH" \
      auto_open_toggle    "Auto-open au login" \
      Quitter             "Quitter" 3>&1 1>&2 2>&3) || exit 0
    [[ $ITEM == Quitter ]] && exit 0
    "$ITEM"
  done

else
  cmd="${1:-}"; shift || true
  [[ -z $cmd ]] && { echo "Usage : sudo $0 --menu  ou  sudo $0 <commande>"; exit 1; }
  "${cmd//-/_}" "$@"
fi
