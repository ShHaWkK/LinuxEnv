#!/usr/bin/env bash
# secure_env.sh — Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail
set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

##############################################################################
# Couleurs & logger
##############################################################################
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'

if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi

LOG="$USER_HOME/secure_env.log"
: >"$LOG"

exec 3>&1
log()     { echo "[$(date +%T)] $*" >>"$LOG"; }
info()    { echo -e "${BLUE}$*${NC}" >&3; }
success() { echo -e "${GREEN}$*${NC}" >&3; }
error()   { echo -e "${RED}$*${NC}" >&2; }

##############################################################################
# Vérifications préalables
##############################################################################
(( EUID == 0 )) || { error "❌ Exécuter en root (sudo)"; exit 1; }

for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd lsblk df pv \
           whiptail gpg ssh-keygen ssh-copy-id tar; do
  command -v "$cmd" &>/dev/null || { error "⛔ $cmd manquant"; exit 1; }
done

##############################################################################
# Variables globales
##############################################################################
DEFAULT_SIZE="5G"

CONTAINER="$USER_HOME/env.img"
MAPPER="env_sec"
MOUNT="$USER_HOME/env_mount"
BACKUP="$USER_HOME/env_backups"

# ---- SSH
SSH_DIR="$MOUNT/ssh"
SSH_TEMPLATES_DIR="$SSH_DIR/conf"
SSH_KEYS_DIR="$SSH_DIR/keys"
ALIAS_FILE_IN_VAULT="$SSH_DIR/aliases_env"
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"
SSH_CONFIG_PATH_ACTIVE=""

# ---- GPG
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"

# ---- Autres
DEFAULT_KEY_TYPE="ed25519"
INTERACTIVE=0

mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" \
         "$SSH_TEMPLATES_DIR" "$SSH_KEYS_DIR" \
         "$GPG_DIR" "$SSH_BACKUP_DIR"

##############################################################################
# Fonctions utilitaires
##############################################################################
spinner() {
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

show_summary() {
  local msg="${1:-}"

  if (( INTERACTIVE )); then
    whiptail --title "Résumé" --textbox "$LOG" 20 70
    [[ -n "$msg" ]] && whiptail --msgbox "$msg" 8 60
  fi

  echo -e "\n— Derniers logs —" >&3
  tail -n 10 "$LOG" >&3
  [[ -n "$msg" ]] && echo "$msg" >&3
}

cleanup_stale() {
  mountpoint -q "$MOUNT"  && umount "$MOUNT"      && log "[OK] démonté"
  cryptsetup status "$MAPPER" &>/dev/null \
    && cryptsetup close "$MAPPER"          && log "[OK] mapper fermé"
}

ensure_env_open() { mountpoint -q "$MOUNT" || open_env; }

set_strict_perms() {
  chmod 700 "$SSH_DIR" "$SSH_TEMPLATES_DIR" "$SSH_KEYS_DIR" "$GPG_DIR"
  chmod 600 "$CONTAINER" || true
}

##############################################################################
# PART I / IV : gestion LUKS + ext4
##############################################################################
ask_pass() {
  read -p "Taille (ex : 5G) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}

  read -s -p "Passphrase LUKS : " PASS;  echo
  read -s -p "Confirmer       : " PASS2; echo

  [[ "$PASS" == "$PASS2" ]] \
    || { error "❌ Passphrases différentes"; exit 1; }
}

install_env() {
  cleanup_stale
  log "== INSTALL =="

  ask_pass

  if [[ -f "$CONTAINER" ]]; then
    whiptail --yesno "Conteneur existant. Écraser ?" 8 50 || return
    rm -f "$CONTAINER"
  fi

  # ---- Création du fichier
  local cnt=${SIZE%[GgMm]}
  [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt * 1024))

  info "Création fichier ($SIZE)…"
  if command -v fallocate &>/dev/null; then
    fallocate -l "$SIZE" "$CONTAINER" & spinner $!
  else
    ( dd if=/dev/zero bs=1M count="$cnt" \
        | pv -s $((cnt * 1024 * 1024)) >"$CONTAINER" ) & spinner $!
  fi
  chmod 600 "$CONTAINER"

  # ---- LUKS + ext4
  info "Formatage LUKS… (tapez YES)"
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!

  info "Ouverture LUKS…"
  printf '%s' "$PASS" \
    | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-

  info "Formatage ext4…"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!

  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"

  chattr +i "$CONTAINER" 2>/dev/null || true
  set_strict_perms

  success "✅ Coffre installé et monté"
  show_summary
}

open_env() {
  log "== OPEN =="

  [[ -f "$CONTAINER" ]] \
    || { error "❌ Conteneur manquant"; return 1; }

  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -s -p "Passphrase LUKS : " PASS; echo
    printf '%s' "$PASS" \
      | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  else
    info "⚠️ LUKS déjà ouvert"
  fi

  mountpoint -q "$MOUNT" \
    || { mount "/dev/mapper/$MAPPER" "$MOUNT"; chmod -R go-rwx "$MOUNT"; }

  set_strict_perms
  success "✅ Coffre ouvert"
  show_summary
}

close_env() {
  log "== CLOSE =="

  mountpoint -q "$MOUNT" \
    && { umount "$MOUNT"; log "[OK] démonté"; } \
    || info "⚠️ Pas monté"

  cryptsetup status "$MAPPER" &>/dev/null \
    && { cryptsetup close "$MAPPER"; log "[OK] LUKS fermé"; } \
    || info "⚠️ Mapper déjà fermé"

  success "✅ Coffre fermé"
  show_summary
}

delete_env() {
  log "== DELETE =="

  close_env
  [[ -f "$CONTAINER" ]] && rm -f "$CONTAINER"
  rmdir "$MOUNT" 2>/dev/null || true

  success "✅ Coffre supprimé"
  show_summary
}

backup_env() {
  log "== BACKUP =="

  local ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"

  success "✅ Backup → $BACKUP"
  show_summary
}

status_env() {
  log "== STATUS =="

  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>/dev/null \
    || echo "mapper fermé" >>"$LOG"

  success "✅ Statut enregistré"
  show_summary
}

##############################################################################
# PART II : gestion GPG
##############################################################################
gpg_setup() {
  log "== GPG SETUP =="
  ensure_env_open

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

  gpg --batch --generate-key gpg-batch
  rm -f gpg-batch

  key=$(gpg --list-secret-keys --with-colons \
        | awk -F: '/^sec/ {print $5;exit}')

  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"

  if whiptail --yesno \
       "Exporter la clé privée dans le coffre ?" 8 60; then
    gpg --export-secret-keys --armor "$key" \
      >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
  fi

  success "✅ Clé GPG générée et sauvegardée"
  show_summary
}

gpg_import() {
  log "== GPG IMPORT =="
  ensure_env_open

  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] import $f"
  done
  shopt -u nullglob

  success "✅ Import GPG terminé"
  show_summary
}

##############################################################################
# PART III : gestion SSH (templates, clés, alias)
##############################################################################
# ---- helpers internes
rewrite_identity_paths() {
  local tpl="$1"
  mapfile -t ids < <(awk '/IdentityFile/ {print $2}' "$tpl")

  for idf in "${ids[@]}"; do
    for f in "$idf" "${idf}.pub"; do
      [[ -f "$f" ]] && cp "$f" "$SSH_KEYS_DIR/" \
        && chmod 600 "$SSH_KEYS_DIR/$(basename "$f")"
    done
    sed -i "s|$idf|$SSH_KEYS_DIR/$(basename "$idf")|g" "$tpl"
  done
  chmod 600 "$tpl"
}

ssh_create_template() {              # depuis ~/.ssh/config
  log "== SSH CREATE TEMPLATE =="
  ensure_env_open

  [[ -f "$SSH_CONFIG" ]] \
    || { whiptail --msgbox "Pas de $SSH_CONFIG" 8 50; return; }

  mapfile -t hosts < <(
    grep -E '^Host[[:space:]]+' "$SSH_CONFIG" | awk '{print $2}'
  )

  (( ${#hosts[@]} )) \
    || { whiptail --msgbox "Aucun Host" 7 40; return; }

  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done

  CH=$(whiptail --menu "Choisissez le Host" 20 60 ${#hosts[@]} \
        "${tags[@]}" 3>&1 1>&2 2>&3) || return

  tpl="$SSH_TEMPLATES_DIR/${CH}.conf"
  awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" \
    "$SSH_CONFIG" >"$tpl"

  rewrite_identity_paths "$tpl"

  success "✅ Template ${CH}.conf créé"
  show_summary
}

ssh_import_hosts() {                 # import multiple
  log "== SSH IMPORT HOSTS =="
  ensure_env_open

  [[ -f "$SSH_CONFIG" ]] \
    || { whiptail --msgbox "Pas de $SSH_CONFIG" 8 50; return; }

  mapfile -t hosts < <(
    grep -E '^Host[[:space:]]+' "$SSH_CONFIG" | awk '{print $2}'
  )

  (( ${#hosts[@]} )) \
    || { whiptail --msgbox "Aucun Host." 7 40; return; }

  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" OFF ); done

  CHS=$(whiptail --checklist "Sélectionnez les hosts" 20 70 \
        ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return

  for CH in $CHS; do
    CH="${CH//\"}"
    tpl="$SSH_TEMPLATES_DIR/${CH}.conf"

    awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" \
      "$SSH_CONFIG" >"$tpl"

    rewrite_identity_paths "$tpl"
    log "[OK] import $CH"
  done

  success "✅ Import terminé"
  show_summary
}

ssh_add_host() {                     # création complète
  log "== SSH ADD HOST =="
  ensure_env_open

  if (( $# >= 4 )); then
    HOST_ALIAS="$1"; HOST_NAME="$2"; HOST_USER="$3"; HOST_PORT="$4"
    KEYTYPE="${5:-$DEFAULT_KEY_TYPE}"
    BITS="${6:-}"
  else
    read -p "Alias (Host)        : " HOST_ALIAS
    [[ -z "$HOST_ALIAS" ]] && { error "Alias vide"; return; }

    read -p "HostName (IP/FQDN)  : " HOST_NAME
    read -p "User [ubuntu]       : " HOST_USER; HOST_USER=${HOST_USER:-ubuntu}
    read -p "Port [22]           : " HOST_PORT; HOST_PORT=${HOST_PORT:-22}
    read -p "Type clé [${DEFAULT_KEY_TYPE}] : " KEYTYPE
    KEYTYPE=${KEYTYPE:-$DEFAULT_KEY_TYPE}

    BITS=""
    if [[ "$KEYTYPE" == rsa ]]; then
      read -p "Bits [4096]        : " BITS
      BITS=${BITS:-4096}
    fi
  fi

  KEY_PATH="$SSH_KEYS_DIR/$HOST_ALIAS"

  [[ -e "$KEY_PATH" ]] \
    && { error "Clé déjà existante"; return; }

  ssh-keygen -t "$KEYTYPE" \
    ${BITS:+-b $BITS} -f "$KEY_PATH" -N "" -C "$HOST_ALIAS" &>/dev/null

  chmod 600 "$KEY_PATH" "$KEY_PATH.pub"

  tpl="$SSH_TEMPLATES_DIR/${HOST_ALIAS}.conf"
  cat >"$tpl" <<EOF
Host $HOST_ALIAS
  HostName $HOST_NAME
  User $HOST_USER
  Port $HOST_PORT
  IdentityFile $KEY_PATH
  IdentitiesOnly yes
EOF

  chmod 600 "$tpl"

  # ---- copie clé publique sur le serveur (option)
  if (( $# < 4 )); then
    if whiptail --yesno \
         "Copier la clé publique sur le serveur ?" 8 60; then
      ssh-copy-id -i "${KEY_PATH}.pub" \
        -p "$HOST_PORT" "${HOST_USER}@${HOST_NAME}" \
        && log "[OK] ssh-copy-id"
    fi
  fi

  success "✅ Host « $HOST_ALIAS » prêt"
  show_summary
}

ssh_choose_template() {              # active un template
  log "== SSH CHOOSE TEMPLATE =="
  ensure_env_open

  mapfile -t tpls < <(
    find "$SSH_TEMPLATES_DIR" -name '*.conf' -printf '%f\n'
  )

  (( ${#tpls[@]} )) \
    || { whiptail --msgbox "Créez d’abord un template" 7 40; return; }

  if (( $# == 1 )); then
    CH="$1"
  else
    tags=(); for t in "${tpls[@]}"; do tags+=( "$t" "" ); done
    CH=$(whiptail --menu "Template actif ?" 15 60 ${#tpls[@]} \
          "${tags[@]}" 3>&1 1>&2 2>&3) || return
  fi

  SSH_CONFIG_PATH_ACTIVE="$SSH_TEMPLATES_DIR/$CH"

  printf 'alias evsh="ssh -F %s %%@"\n' \
    "$SSH_CONFIG_PATH_ACTIVE" >"$ALIAS_FILE_IN_VAULT"

  chmod 600 "$ALIAS_FILE_IN_VAULT"
  ln -sf "$ALIAS_FILE_IN_VAULT" "$ALIAS_LINK"

  for rc in "$USER_HOME/.bashrc" "$USER_HOME/.zshrc"; do
    [[ -f "$rc" ]] && grep -qF ".aliases_env" "$rc" \
      || echo "source ~/.aliases_env" >>"$rc"
  done

  success "✅ Template actif : $CH"
  show_summary
}

##############################################################################
# Outils SSH supplémentaires
##############################################################################
ssh_delete() {
  log "== SSH DELETE =="
  ensure_env_open

  rm -rf "$SSH_DIR"/*
  mkdir -p "$SSH_TEMPLATES_DIR" "$SSH_KEYS_DIR"

  success "✅ Vault SSH vidé"
  show_summary
}

ssh_backup() {
  log "== SSH BACKUP =="
  ensure_env_open

  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .

  whiptail --msgbox \
    "Backup : $SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" 8 70

  success "✅ Backup SSH créé"
  show_summary
}

restore_ssh_wallet() {
  log "== SSH RESTORE =="
  ensure_env_open

  mapfile -t bs < <(
    ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null || true
  )

  (( ${#bs[@]} )) \
    || { whiptail --msgbox "Pas de backup" 7 40; return; }

  tags=(); for b in "${bs[@]}"; do
    tags+=( "$(basename "$b")" "" )
  done

  CH=$(whiptail --menu "Choisissez backup" 15 60 ${#bs[@]} \
        "${tags[@]}" 3>&1 1>&2 2>&3) || return

  rm -rf "$SSH_DIR"/*
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"

  success "✅ Backup restauré"
  show_summary
}

auto_open_toggle() {
  log "== AUTO-OPEN =="

  line="$PWD/secure_env.sh open_env &>/dev/null"

  if grep -qF "$line" "$USER_HOME/.bashrc"; then
    sed -i "\|$line|d" "$USER_HOME/.bashrc"
    success "✅ Auto-open désactivé"
  else
    echo "$line" >>"$USER_HOME/.bashrc"
    success "✅ Auto-open activé"
  fi

  show_summary
}

##############################################################################
# Menu interactif & CLI directe
##############################################################################
cleanup_stale

if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1

  while true; do
    TOP=$(whiptail --title "Coffre sécurisé" --menu "Section" 15 60 4 \
          Environnement "LUKS/ext4" \
          Cryptographie "GPG"       \
          SSH           "SSH"       \
          Quitter       "Quitter"   3>&1 1>&2 2>&3) || exit 0

    case $TOP in
      Environnement)
        ACTION=$(whiptail --menu "Choisissez" 20 60 7 \
                 install_env "Installer"  \
                 open_env    "Ouvrir"     \
                 close_env   "Fermer"     \
                 delete_env  "Supprimer"  \
                 backup_env  "Backup"     \
                 status_env  "Statut"     \
                 Retour      "Retour"     3>&1 1>&2 2>&3)
        [[ $ACTION != Retour ]] && "$ACTION"
        ;;

      Cryptographie)
        ACTION=$(whiptail --menu "Choisissez" 15 60 3 \
                 gpg_setup  "Créer une clé" \
                 gpg_import "Importer GPG"  \
                 Retour     "Retour"        3>&1 1>&2 2>&3)
        [[ $ACTION != Retour ]] && "$ACTION"
        ;;

      SSH)
        ACTION=$(whiptail --menu "Choisissez" 23 60 11 \
                 ssh_add_host        "Créer un Host neuf" \
                 ssh_create_template "Template depuis ~/.ssh/config" \
                 ssh_import_hosts    "Importer plusieurs Hosts"      \
                 ssh_choose_template "Activer un template & alias"   \
                 ssh_delete          "Vider le coffre SSH"           \
                 ssh_backup          "Sauvegarder le coffre SSH"     \
                 restore_ssh_wallet  "Restaurer un backup"           \
                 auto_open_toggle    "Auto-open au login"            \
                 Retour              "Retour"                        3>&1 1>&2 2>&3)
        [[ $ACTION != Retour ]] && "$ACTION"
        ;;

      Quitter) exit 0 ;;
    esac
  done

else
  FUNC="${1//-/_}"
  shift || true

  if [[ -n "$FUNC" && $(type -t "$FUNC") == "function" ]]; then
    "$FUNC" "$@"
  else
    echo "Usage : $0 --menu  OU  $0 <fonction> [options]" >&2
    exit 1
  fi
fi
