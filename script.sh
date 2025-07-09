#!/bin/bash
# Author  : ShHawk alias Alexandre Uzan
# Sujet   : Environnement Sécurisé complet (LUKS, GPG, SSH)

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# Options
VERBOSE=0
DRYRUN=0

# Couleurs
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

# Helpers
info()    { echo -e "${BLUE}$*${NC}"; }
success() { echo -e "${GREEN}$*${NC}"; }
warning() { echo -e "${YELLOW}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }
prompt()  { echo -en "${BLUE}$*${NC}"; }

run_cmd() {
  if [[ $DRYRUN -eq 1 ]]; then
    info "[DRY-RUN] $*"
  else
    [[ $VERBOSE -eq 1 ]] && info "$*"
    "$@"
  fi
}

run_cmd_output() {
  if [[ $DRYRUN -eq 1 ]]; then
    info "[DRY-RUN] $*"
    return 0
  else
    [[ $VERBOSE -eq 1 ]] && info "$*"
    "$@"
  fi
}

(( EUID == 0 )) || { error "exécuter en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid gpg; do
  command -v "$cmd" >/dev/null 2>&1 || { error "$cmd manquant"; exit 1; }
done

# Variables
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPING="env_sec"
MOUNT_POINT="$HOME/env_mount"
ALIAS_LINK="$HOME/.aliases_env"

# Prépare les dossiers
mkdir -p "${CONTAINER%/*}" "$MOUNT_POINT"

# Affichages
show_lsblk() { echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; echo; }
show_df()    { echo; df -Th | grep -E "$MAPPING|Filesystem"; echo; }
show_blkid() { echo; blkid /dev/mapper/"$MAPPING" 2>/dev/null || echo "(pas de mapping ouvert)"; echo; }

# Utilitaires
read_size_and_pass() {
  read -p "Taille du conteneur (ex: 5G, 500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS; echo
  read -s -p "Confirmer le mot de passe : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "mots de passe différents"; exit 1; }
}

attach_loop() {
  LOOPDEV=$(run_cmd_output losetup --find --show "$CONTAINER")
  [[ $DRYRUN -eq 1 ]] || echo "$LOOPDEV" >"$LOOP_FILE"
}

detach_loop() {
  [[ -f "$LOOP_FILE" ]] && {
    run_cmd losetup -d "$(cat "$LOOP_FILE")"
    run_cmd rm -f "$LOOP_FILE"
  }
}

unlock_volume() {
  if [[ $DRYRUN -eq 1 ]]; then
    info "[DRY-RUN] cryptsetup open --type luks1 $1 $MAPPING"
  else
    printf '%s' "$PASS" | cryptsetup open --type luks1 --key-file=- "$1" "$MAPPING"
  fi
}

lock_volume() {
  run_cmd cryptsetup close "$MAPPING"
}

format_volume() {
  run_cmd mkfs.ext4 /dev/mapper/"$MAPPING"
}

mount_volume() {
  run_cmd mount /dev/mapper/"$MAPPING" "$MOUNT_POINT"
}

umount_volume() {
  run_cmd umount "$MOUNT_POINT" 2>/dev/null || :
}

set_permissions() {
  run_cmd chmod 600 "$CONTAINER"
  run_cmd chmod -R go-rwx "$MOUNT_POINT"
}

# Commandes principales
install() {
  echo ">>> INSTALL <<<"
  show_lsblk
  read_size_and_pass

  [[ -f "$CONTAINER" ]] && { error "conteneur existe"; exit 1; }
  cryptsetup status "$MAPPING" &>/dev/null && { error "mapping existe"; exit 1; }

  if ! run_cmd fallocate -l "$SIZE" "$CONTAINER" 2>/dev/null; then
    COUNT=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && COUNT=$((COUNT*1024))
    run_cmd dd if=/dev/zero of="$CONTAINER" bs=1M count="$COUNT" status=progress
  fi
  attach_loop; show_lsblk
  if [[ $DRYRUN -eq 1 ]]; then
    info "[DRY-RUN] cryptsetup luksFormat $LOOPDEV"
  else
    printf '%s' "$PASS" | cryptsetup luksFormat --type luks1 --batch-mode "$LOOPDEV" --key-file=-
  fi
  unlock_volume "$LOOPDEV"
  format_volume
  mount_volume
  set_permissions
  show_lsblk; show_df; show_blkid
  success "Environnement installé et monté sur $MOUNT_POINT"
}

open() {
  echo ">>> OPEN <<<"
  show_lsblk
  [[ ! -f "$CONTAINER" ]] && { error "pas de conteneur"; exit 1; }
  [[ -f "$LOOP_FILE" ]] || attach_loop

  if [[ ! -e /dev/mapper/"$MAPPING" ]]; then
    read -s -p "Mot de passe LUKS : " PASS; echo
    unlock_volume "$(cat "$LOOP_FILE")"
    success "Volume déverrouillé"
  fi
  mountpoint -q "$MOUNT_POINT" || mount_volume
  set_permissions
  show_df
}

close() {
  echo ">>> CLOSE <<<"
  umount_volume && success "Démonté"
  [[ -e /dev/mapper/"$MAPPING" ]] && (lock_volume && success "Verrouillé")
  detach_loop && success "Loop détaché"
  show_lsblk
}

delete() {
  echo ">>> DELETE <<<"
  close || :
  rm -f "$CONTAINER" && success "Conteneur supprimé"
  rmdir "$MOUNT_POINT" 2>/dev/null || :
}

status() {
  echo ">>> STATUS <<<"
  run_cmd lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT
  run_cmd mount | grep "$MAPPING" || true
  run_cmd blkid "/dev/mapper/$MAPPING" || true
  run_cmd cryptsetup status "$MAPPING" || true
  [[ -f "$ALIAS_LINK" ]] && success "Alias présent : $ALIAS_LINK" || warning "Alias absent : $ALIAS_LINK"
  [[ -f "$MOUNT_POINT/ssh_config" ]] && success "Template SSH présent" || warning "Template SSH absent"
}

# GPG
gpg_setup() {
  echo ">>> GPG SETUP <<<"
  read -p "Nom : " NAME
  read -p "Email : " EMAIL
  read -p "Commentaire : " COMMENT

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

  run_cmd gpg --batch --generate-key gpg-batch
  run_cmd rm -f gpg-batch
  KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}' | head -n1)
  run_cmd gpg --export --armor "$KEYID" > "$MOUNT_POINT/public_$KEYID.gpg"
  run_cmd gpg --export-secret-keys --armor "$KEYID" > "$MOUNT_POINT/private_$KEYID.gpg"
  run_cmd chmod 600 "$MOUNT_POINT/private_$KEYID.gpg"
  success "Clés exportées dans le coffre"
}

gpg_import() {
  echo ">>> GPG IMPORT <<<"
  shopt -s nullglob
  files=("$MOUNT_POINT"/*.gpg)
  shopt -u nullglob
  [[ ${#files[@]} -eq 0 ]] && { warning "aucune clé à importer"; return 1; }
  for f in "${files[@]}"; do
    run_cmd gpg --import "$f" && success "Importé $f"
  done
}

gpg_export() {
  echo ">>> GPG EXPORT <<<"
  KEYIDS=$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/ {print $5}')
  [[ -z "$KEYIDS" ]] && { warning "aucune clé à exporter"; return 1; }
  for id in $KEYIDS; do
    run_cmd gpg --export --armor "$id" > "$MOUNT_POINT/public_${id}.gpg"
    run_cmd gpg --export-secret-keys --armor "$id" > "$MOUNT_POINT/private_${id}.gpg"
    run_cmd chmod 600 "$MOUNT_POINT/private_${id}.gpg"
    success "Clés $id exportées dans le coffre"
  done
}

# SSH
ssh_setup() {
  echo ">>> SSH SETUP <<<"

  # Crée ~/.ssh/config s'il n'existe pas
  [[ -f "$HOME/.ssh/config" ]] || {
    run_cmd touch "$HOME/.ssh/config"
    run_cmd chmod 600 "$HOME/.ssh/config"
  }

  # Si aucun Host n'est défini, proposer la création d'un host de test
  if ! grep -q '^Host ' "$HOME/.ssh/config"; then
    read -p "Aucun host SSH trouvé. Créer un host de test ? [y/N] " ans
    if [[ $ans =~ ^[Yy]$ ]]; then
      TEST_KEY="$HOME/.ssh/id_rsa_test"
      run_cmd ssh-keygen -t rsa -b 2048 -f "$TEST_KEY" -N "" -C "clé de test partiel"
      run_cmd chmod 600 "$TEST_KEY"

      cat >> "$HOME/.ssh/config" <<EOF

Host test-host
  HostName 192.168.1.50
  User $(whoami)
  IdentityFile $TEST_KEY
EOF
      success "Host 'test-host' ajouté dans ~/.ssh/config"
    fi
  fi

  # Lister tous les Host définis
  echo "Hosts disponibles :"
  grep '^Host ' "$HOME/.ssh/config" | awk '{print " -", $2}'

  # Choix de l’host à importer
  read -p "Host à importer : " CHOSEN

  TEMPLATE="$MOUNT_POINT/ssh_config"
  ALIAS_FILE="$MOUNT_POINT/.aliases"

  # Extrait la section choisie et la stocke dans le coffre
  awk "/^Host $CHOSEN\$/,/^Host /" "$HOME/.ssh/config" > "$TEMPLATE"

  # Copie la clé privée dans le coffre si présente
  if grep -q "IdentityFile" "$TEMPLATE"; then
    OLD_KEY=$(grep IdentityFile "$TEMPLATE" | awk '{print $2}')
    NEW_KEY="$MOUNT_POINT/$(basename "$OLD_KEY")"
    run_cmd sed -i "s|$OLD_KEY|$NEW_KEY|" "$TEMPLATE"
    run_cmd cp "$OLD_KEY" "$NEW_KEY"
    run_cmd chmod 600 "$NEW_KEY"
  fi

  # Crée l’alias et le lien symbolique
  echo "alias evsh='ssh -F $TEMPLATE'" > "$ALIAS_FILE"
  run_cmd ln -sf "$ALIAS_FILE" "$ALIAS_LINK"

  success "SSH $CHOSEN importé dans le coffre et alias evsh prêt à l’emploi"
}


usage() {
  cat <<EOF
Usage: $0 [-v] [-n] <commande>
Commandes: install, open, close, delete, gpg-setup, gpg-import, gpg-export, ssh-setup, status
Options:
  -v           mode verbeux
  -n           dry-run
  -h, --help   afficher cette aide
EOF
}

parse_args() {
  local opts
  opts=$(getopt -o hvn -l help -- "$@") || { usage; exit 1; }
  eval set -- "$opts"
  while true; do
    case "$1" in
      -v) VERBOSE=1; shift ;;
      -n) DRYRUN=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --) shift; break ;;
      *) usage; exit 1 ;;
    esac
  done
  COMMAND="${1:-}"
  [[ -z "$COMMAND" ]] && { usage; exit 1; }
}

parse_args "$@"
[[ $VERBOSE -eq 1 ]] && set -x

case "$COMMAND" in
  install)     install ;;
  open)        open ;;
  close)       close ;;
  delete)      delete ;;
  gpg-setup)   gpg_setup ;;
  gpg-import)  gpg_import ;;
  gpg-export)  gpg_export ;;
  ssh-setup)   ssh_setup ;;
  status)      status ;;
  *)           usage ;;
esac
