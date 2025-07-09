#!/bin/bash
# Author  : ShHawk alias Alexandre Uzan
# Sujet   : Environnement Sécurisé complet (LUKS, GPG, SSH)

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ------------------------------
# Options & Couleurs
# ------------------------------

VERBOSE=0
DRYRUN=0

RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; BLUE='\e[34m'; NC='\e[0m'

info()    { [[ $VERBOSE -eq 1 ]] && echo -e "${BLUE}$*${NC}"; }
success() { echo -e "${GREEN}$*${NC}"; }
warning() { echo -e "${YELLOW}$*${NC}"; }
error()   { echo -e "${RED}$*${NC}" >&2; }

# Wrapper pour exécuter ou simuler une commande
run_cmd() {
  if [[ $DRYRUN -eq 1 ]]; then
    info "[DRY-RUN] $*"
  else
    info "$*"
    "$@"
  fi
}

# Wrapper pour capturer la sortie d'une commande en mode dry-run ou normal
run_cmd_output() {
  if [[ $DRYRUN -eq 1 ]]; then
    info "[DRY-RUN] $*"
    echo ""
  else
    info "$*"
    "$@"
  fi
}

# ------------------------------
# Vérifications initiales
# ------------------------------
(( EUID == 0 )) || { error "exécuter en root"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid gpg; do
  command -v "$cmd" >/dev/null 2>&1 || { error "$cmd manquant"; exit 1; }
done

# ------------------------------
# Variables clés
# ------------------------------
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
LOOP_FILE="$HOME/env.loop"
MAPPING="env_sec"
MOUNT_POINT="$HOME/env_mount"
ALIAS_LINK="$HOME/.aliases_env"

# Crée les répertoires si nécessaire
mkdir -p "${CONTAINER%/*}" "$MOUNT_POINT"

# ------------------------------
# Affichages d’état
# ------------------------------
show_lsblk() { echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT; echo; }
show_df()    { echo; df -Th | grep -E "$MAPPING|Filesystem"; echo; }
show_blkid() { echo; blkid /dev/mapper/"$MAPPING" 2>/dev/null || echo "(pas de mapping ouvert)"; echo; }

# ------------------------------
# Utilitaires
# ------------------------------
read_size_and_pass() {
  # Demande taille + mot de passe LUKS avec confirmation
  read -p "Taille du conteneur (ex: 5G, 500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Mot de passe LUKS : " PASS; echo
  read -s -p "Confirmer le mot de passe : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "mots de passe différents"; exit 1; }
}

attach_loop() {
  # Attache env.img à un loop device
  LOOPDEV=$(run_cmd_output losetup --find --show "$CONTAINER")
  [[ $DRYRUN -eq 0 ]] && echo "$LOOPDEV" >"$LOOP_FILE"
}

detach_loop() {
  # Détache le loop device
  [[ -f "$LOOP_FILE" ]] && {
    run_cmd losetup -d "$(cat "$LOOP_FILE")"
    run_cmd rm -f "$LOOP_FILE"
  }
}

unlock_volume() {
  # Déverrouille le volume LUKS
  printf '%s' "$PASS" | cryptsetup open --type luks1 --key-file=- "$1" "$MAPPING"
}

lock_volume() {
  # Verrouille le volume LUKS
  run_cmd cryptsetup close "$MAPPING"
}

format_volume() {
  # Formate en ext4
  run_cmd mkfs.ext4 /dev/mapper/"$MAPPING"
}

mount_volume() {
  # Monte sur le point défini
  run_cmd mount /dev/mapper/"$MAPPING" "$MOUNT_POINT"
}

umount_volume() {
  # Démontage silencieux
  run_cmd umount "$MOUNT_POINT" 2>/dev/null || :
}

set_permissions() {
  # Sécurise les permissions
  run_cmd chmod 600 "$CONTAINER"
  run_cmd chmod -R go-rwx "$MOUNT_POINT"
}

# ------------------------------
# Commandes principales
# ------------------------------
install() {
  echo ">>> install <<<"; show_lsblk
  read_size_and_pass

  [[ -f "$CONTAINER" ]] && { error "conteneur existe"; exit 1; }
  cryptsetup status "$MAPPING" &>/dev/null && { error "mapping existe"; exit 1; }

  # Création du conteneur
  if ! run_cmd fallocate -l "$SIZE" "$CONTAINER" 2>/dev/null; then
    COUNT=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && COUNT=$((COUNT*1024))
    run_cmd dd if=/dev/zero of="$CONTAINER" bs=1M count="$COUNT" status=progress
  fi
  show_lsblk

  # Boucle + LUKS
  attach_loop; show_lsblk
  printf '%s' "$PASS" | \
    cryptsetup luksFormat --type luks1 --batch-mode "$LOOPDEV" --key-file=-
  show_lsblk

  # Déverrouille, formate, monte
  unlock_volume "$LOOPDEV"; show_lsblk
  format_volume; show_lsblk
  mount_volume; set_permissions
  show_lsblk; show_df; show_blkid

  success "environnement installé et monté sur $MOUNT_POINT"
}

open() {
  echo ">>> open <<<"; show_lsblk
  [[ ! -f "$CONTAINER" ]] && { error "pas de conteneur"; exit 1; }
  [[ -f "$LOOP_FILE" ]] || attach_loop

  if [[ ! -e /dev/mapper/"$MAPPING" ]]; then
    read -s -p "Mot de passe LUKS : " PASS; echo
    unlock_volume "$(cat "$LOOP_FILE")"
    success "volume déverrouillé"
  else
    warning "mapping déjà ouvert"
  fi
  show_lsblk

  mountpoint -q "$MOUNT_POINT" || (mount_volume && set_permissions && success "monté sur $MOUNT_POINT")
  show_df
}

close() {
  echo ">>> close <<<"; show_lsblk
  umount_volume && success "démonté"
  [[ -e /dev/mapper/"$MAPPING" ]] && lock_volume && success "verrouillé"
  detach_loop && success "loop détaché"
  show_lsblk
}

delete() {
  echo ">>> delete <<<"
  close || :
  [[ -f "$CONTAINER" ]] && rm -f "$CONTAINER" && success "conteneur supprimé"
  rmdir "$MOUNT_POINT" 2>/dev/null || :
  show_lsblk
}

status() {
  echo ">>> status <<<"
  run_cmd lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT
  df -Th | grep "$MAPPING" || echo "(pas monté)"
  blkid "/dev/mapper/$MAPPING" 2>/dev/null || echo "(pas de mapping)"
  cryptsetup status "$MAPPING" 2>/dev/null || echo "(mapping fermé)"
}

gpg_setup() {
  echo ">>> gpg-setup <<<"
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
  rm -f gpg-batch
  KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5; exit}')
  run_cmd gpg --export --armor "$KEYID" >"$MOUNT_POINT/public_$KEYID.gpg"
  run_cmd gpg --export-secret-keys --armor "$KEYID" >"$MOUNT_POINT/private_$KEYID.gpg"
  run_cmd chmod 600 "$MOUNT_POINT/private_$KEYID.gpg"
  success "clés GPG exportées dans le coffre"
}

gpg_import() {
  echo ">>> gpg-import <<<"
  for f in "$MOUNT_POINT"/*.gpg; do
    run_cmd gpg --import "$f" && success "importé $f"
  done
}

gpg_export() {
  echo ">>> gpg-export <<<"
  for id in $(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}'); do
    run_cmd gpg --export --armor "$id" >"$MOUNT_POINT/public_${id}.gpg"
    run_cmd gpg --export-secret-keys --armor "$id" >"$MOUNT_POINT/private_${id}.gpg"
    run_cmd chmod 600 "$MOUNT_POINT/private_${id}.gpg"
    success "clés $id exportées"
  done
}

ssh_setup() {
  echo ">>> ssh-setup <<<"
  [[ ! -f "$HOME/.ssh/config" ]] && run_cmd touch "$HOME/.ssh/config" && run_cmd chmod 600 "$HOME/.ssh/config"
  if ! grep -q '^Host ' "$HOME/.ssh/config"; then
    read -p "Créer un host test SSH ? [y/N] " ANS
    [[ $ANS =~ ^[Yy]$ ]] && {
      run_cmd ssh-keygen -t rsa -b 2048 -f "$HOME/.ssh/id_rsa_test" -N "" -C "test-host"
      cat >>"$HOME/.ssh/config" <<EOF

Host test-host
  HostName 192.168.1.50
  User $(whoami)
  IdentityFile $HOME/.ssh/id_rsa_test
EOF
      success "host 'test-host' ajouté"
    }
  fi
  grep '^Host ' "$HOME/.ssh/config" | awk '{print " -", $2}'
  read -p "Host à importer : " CHOSEN
  TEMPLATE="$MOUNT_POINT/ssh_config"
  awk "/^Host $CHOSEN\$/,/^Host /" "$HOME/.ssh/config" >"$TEMPLATE"
  [[ -f "$TEMPLATE" ]] && success "SSH config exportée vers $TEMPLATE"
  echo "alias evsh='ssh -F $TEMPLATE'" >"$ALIAS_LINK"
  ln -sf "$ALIAS_LINK" "$HOME/.aliases_env"
  success "alias 'evsh' prêt"
}

# ------------------------------
# Aide & parsing
# ------------------------------
usage() {
  cat <<EOF
Usage: $0 [-v] [-n] <commande>
Commandes :
  install    créer et monter l'environnement
  open       déverrouiller et monter
  close      démonter et verrouiller
  delete     supprimer conteneur + loop
  status     afficher état (lsblk, df, blkid)
  gpg-setup  générer clés GPG dans le coffre
  gpg-import importer toutes les .gpg du coffre
  gpg-export exporter toutes vos clés dans le coffre
  ssh-setup  importer un host SSH et générer alias evsh
Options :
  -v         verbeux
  -n         dry-run
  -h, --help afficher cette aide
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
  COMMAND="${1:-}"; [[ -z "$COMMAND" ]] && usage
}

parse_args "$@"
[[ $VERBOSE -eq 1 ]] && set -x

# Exécution
case "$COMMAND" in
  install)     install ;;
  open)        open ;;
  close)       close ;;
  delete)      delete ;;
  status)      status ;;
  gpg-setup)   gpg_setup ;;
  gpg-import)  gpg_import ;;
  gpg-export)  gpg_export ;;
  ssh-setup)   ssh_setup ;;
  *)           usage ;;
esac
