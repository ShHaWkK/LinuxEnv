#!/usr/bin/env bash
##############################################################################
# Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail
# Authors : ShHawk alias Alexandre UZAN && Julien Khalifa
# Fonctionnalités : Install / open / close / delete / backup d’un conteneur LUKS + ext4
#  - Gestion de paires GPG : génération, export, import
#  - Gestion SSH « vault » : templates, import de hosts, backup, alias evsh
#
# Exécution :
#   sudo ./secure_env.sh --menu         # interface Whiptail
#   sudo ./secure_env.sh <fonction> …   # mode CLI direct
#
##############################################################################
set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

##############################################################################
# Couleurs & journal                                                           
##############################################################################
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'

# Si sudo, $HOME vaut /root : on bascule sur le vrai home de l’utilisateur
if [[ -n ${SUDO_USER-} && $SUDO_USER != root ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi

LOG="$USER_HOME/secure_env.log"  # trace complète
: >"$LOG" # réinitialise le fichier
exec 3>&1   # descripteur pour stdout  user 

log()    { echo "[$(date +%T)] $*" >>"$LOG"; }
info()   { echo -e "${BLUE}$*${NC}"  >&3; log "$*"; }
success(){ echo -e "${GREEN}$*${NC}" >&3; log "$*"; }
error()  { echo -e "${RED}$*${NC}"   >&2; log "ERREUR : $*"; }

##############################################################################
# Dépendances minimales (stop script si manquantes)                            
##############################################################################
(( EUID==0 )) || { error "[X] Exécuter en root (sudo)"; exit 1; }

for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid \
           pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "[X] $cmd manquant"; exit 1; }
done

##############################################################################
# Variables globales                                                          
##############################################################################
DEFAULT_SIZE="5G"

# Emplacements principaux
CONTAINER="$USER_HOME/env.img" # fichier conteneur LUKS
MAPPER="env_sec" # nom du device mapper
MOUNT="$USER_HOME/env_mount" # point de montage
BACKUP="$USER_HOME/env_backups"  # dossier de backups

# Sous-répertoires du coffre
SSH_DIR="$MOUNT/ssh"   # racine vault SSH
SSH_CONFIG_PATH="$SSH_DIR/ssh_config"   # fichier composite de conf
SSH_ALIAS_FILE="$SSH_DIR/ssh_aliases"   # fichier contenant alias evsh
GPG_DIR="$MOUNT/gpg"    # vault GPG
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"  # backups SSH

ALIAS_LINK="$USER_HOME/.aliases_env" # symlink vers l’alias evsh
SSH_CONFIG="$USER_HOME/.ssh/config"  # config SSH existante
INTERACTIVE=0    # passe à 1 quand --menu

# Création arbres
mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" \
         "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

##############################################################################
# Fonctions utilitaires générales                                             
##############################################################################

### spinner : petite roue pendant une tâche longue (si pv indispo)
spinner() {
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

### show_summary : affiche la fin du log + message optionnel
show_summary() {
  local msg="${1:-}"
  if (( INTERACTIVE )); then
    whiptail --title "Résumé" --textbox "$LOG" 20 70
    [[ -n $msg ]] && whiptail --msgbox "$msg" 8 50
  fi
  echo -e "\n— Derniers logs —" >&3
  tail -n 10 "$LOG" >&3
  [[ -n $msg ]] && echo "$msg" >&3
}

### cleanup_stale : démonte et ferme le mapper s’ils trainent
cleanup_stale() {
  mountpoint -q "$MOUNT" && umount "$MOUNT" && log "[OK] démonté résiduel"
  cryptsetup status "$MAPPER" &>/dev/null && cryptsetup close "$MAPPER" \
    && log "[OK] mapper fermé résiduel"
}

### ensure_env_open : ouvre le coffre si nécessaire
ensure_env_open() { mountpoint -q "$MOUNT" || open_env; }

##############################################################################
# PART I & IV – Fonctions LUKS / ext4                                        
##############################################################################

### ask_pass : demande taille & passphrase
ask_pass() {
  read -p "Taille conteneur (ex : 5G) [$DEFAULT_SIZE] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer        : " PASS2; echo
  [[ $PASS == "$PASS2" ]] || { error "[X] Passphrases différentes"; exit 1; }
}

### install_env : crée le fichier, chiffre LUKS, formate ext4, monte
install_env() {
  cleanup_stale; log "== INSTALL =="; ask_pass

  # écrasement éventuel
  if [[ -f $CONTAINER ]] && ! whiptail --yesno \
       "Conteneur existe ; l’écraser ?" 8 50; then return; fi
  rm -f "$CONTAINER"

  # création fichier sparse (fallocate) ou dd + pv
  info "Création fichier $SIZE…"
  if fallocate -l "$SIZE" "$CONTAINER"; then :
  else
    local cnt=${SIZE%[GgMm]}; [[ $SIZE =~ [Gg]$ ]] && cnt=$((cnt*1024))
    (dd if=/dev/zero bs=1M count="$cnt" \
      | pv -s $((cnt*1024*1024)) >"$CONTAINER") & spinner $!
  fi
  chmod 600 "$CONTAINER"

  # LUKS
  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=-
  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-

  # ext4 & montage
  mkfs.ext4 -q "/dev/mapper/$MAPPER"
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"

  success "Coffre installé & monté"
  show_summary
}

### open_env : ouvre mapper + monte si besoin
open_env() {
  log "== OPEN =="; [[ -f $CONTAINER ]] || { error "[X] Conteneur absent"; return; }

  cryptsetup status "$MAPPER" &>/dev/null || {
    read -s -p "Passphrase LUKS : " PASS; echo
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  }
  mountpoint -q "$MOUNT" || mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"

  success "Coffre ouvert"
  show_summary
}

### close_env : démonte & ferme mapper
close_env() {
  log "== CLOSE =="; mountpoint -q "$MOUNT" && umount "$MOUNT"
  cryptsetup status "$MAPPER" &>/dev/null && cryptsetup close "$MAPPER"
  success "Coffre fermé"; show_summary
}

### delete_env : supprime définitivement le fichier conteneur
delete_env() {
  close_env; rm -f "$CONTAINER"; rmdir "$MOUNT" 2>/dev/null || :
  success "Coffre supprimé"; show_summary
}

### backup_env : copie conteneur + header
backup_env() {
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"
  success "Backup créé dans $BACKUP"; show_summary
}

### status_env : écrit infos device + mapper dans le log
status_env() {
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>/dev/null || echo "mapper fermé" >>"$LOG"
  success "Statut enregistré"; show_summary
}

##############################################################################
# PART II – Fonctions GPG                                                    
##############################################################################

### gpg_setup : génère une paire, sauvegarde pub/priv dans le coffre
gpg_setup() {
  log "== GPG SETUP =="; ensure_env_open

  read -p "Nom        : " N
  read -p "Email      : " E
  read -p "Commentaire: " C

  cat >gpg-batch <<EOF
%no-protection
Key-Type: default
Name-Real: $N
Name-Comment: $C
Name-Email: $E
Expire-Date: 0
%commit
EOF
  gpg --batch --generate-key gpg-batch && rm gpg-batch

  key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"

  if whiptail --yesno "Sauvegarder aussi la clé privée ?" 8 60; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
  fi

  success "Clé GPG $key générée"; show_summary
}

### gpg_import : importe toutes les .gpg du coffre dans le trousseau
gpg_import() {
  log "== GPG IMPORT =="; ensure_env_open
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do gpg --import "$f"; done
  shopt -u nullglob
  success "Import terminé"; show_summary
}

### gpg_export : exporte toutes les clés secrètes du trousseau vers le coffre
gpg_export() {
  log "== GPG EXPORT =="; ensure_env_open
  mkdir -p "$GPG_DIR"
  mapfile -t keys < <(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}')
  for k in "${keys[@]}"; do
    gpg --export --armor "$k"          >"$GPG_DIR/public_${k}.gpg"
    gpg --export-secret-keys --armor "$k" >"$GPG_DIR/private_${k}.gpg"
    chmod 600 "$GPG_DIR/private_${k}.gpg"
  done
  success "Export GPG terminé"; show_summary
}

##############################################################################
# PART III – Fonctions SSH (vault)                                           
##############################################################################

### ssh_create_template : extrait un Host de ~/.ssh/config vers vault
ssh_create_template() {
  log "== SSH CREATE TEMPLATE =="; ensure_env_open
  [[ -f $SSH_CONFIG ]] || { whiptail --msgbox "Pas de $SSH_CONFIG" 8 50; return; }

  mapfile -t hosts < <(grep -E '^Host[[:space:]]+' "$SSH_CONFIG" | awk '{print $2}')
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun Host" 7 40; return; }

  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez un Host" 20 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return

  awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" "$SSH_CONFIG" >"$SSH_CONFIG_PATH"
  idf=$(awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" "$SSH_CONFIG" \
        | awk '/IdentityFile/ {print $2;exit}')
  if [[ -n $idf ]]; then
    cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")"
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_CONFIG_PATH"
  fi

  whiptail --msgbox "Template créé pour $CH" 7 50
}

### ssh_setup_alias : écrit l’alias « evsh » (utilise $SSH_CONFIG_PATH)
ssh_setup_alias() {
  log "== SSH SETUP ALIAS =="; ensure_env_open
  echo "alias evsh='ssh -F $SSH_CONFIG_PATH'" >"$SSH_ALIAS_FILE"
  chmod 644 "$SSH_ALIAS_FILE"
  ln -sf "$SSH_ALIAS_FILE" "$ALIAS_LINK"

  success "Alias evsh prêt – source ~/.aliases_env"
  show_summary
}

### ssh_import_host : ajoute un Host de ~/.ssh/config (interactive)
ssh_import_host() {
  log "== SSH IMPORT HOST =="; ensure_env_open
  [[ -f $SSH_CONFIG ]] || { whiptail --msgbox "Pas de $SSH_CONFIG" 7 40; return; }

  mapfile -t hosts < <(grep -E '^Host[[:space:]]+' "$SSH_CONFIG" | awk '{print $2}')
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez Host" 20 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return

  block=$(awk "/^Host[[:space:]]+$CH\\b/,/^[Hh]ost[[:space:]]/" "$SSH_CONFIG")
  printf '%s\n' "$block" >>"$SSH_CONFIG_PATH"

  while read -r line; do
    if [[ $line =~ [Ii]dentity[Ff]ile[[:space:]]+(.+) ]]; then
      idf=${BASH_REMATCH[1]}
      base=$(basename "$idf")
      cp "$idf" "$SSH_DIR/$base" && chmod 600 "$SSH_DIR/$base"
      [[ -f ${idf}.pub ]] && cp "${idf}.pub" "$SSH_DIR/${base}.pub"
      sed -i "s|$idf|$SSH_DIR/$base|g" "$SSH_CONFIG_PATH"
    fi
  done <<<"$block"

  success "Host $CH importé"; show_summary
}

### ssh_delete : vide entièrement le vault SSH
ssh_delete() { ensure_env_open; rm -rf "$SSH_DIR"/*; success "Vault SSH vidé"; }

### ssh_backup : archive le dossier SSH
ssh_backup() {
  ensure_env_open; local ts; ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  success "Backup : $SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz"; show_summary
}

### restore_ssh_wallet : restaure un backup existant
restore_ssh_wallet() {
  ensure_env_open
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  (( ${#bs[@]} )) || { whiptail --msgbox "Pas de backup SSH" 7 40; return; }
  tags=(); for b in "${bs[@]}"; do tags+=( "$(basename "$b")" "" ); done
  CH=$(whiptail --menu "Choisissez backup" 15 60 ${#bs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  success "SSH restauré : $CH"; show_summary
}

### auto_open_toggle : ajoute ou enlève auto-open dans ~/.bashrc
auto_open_toggle() {
  local line="$PWD/secure_env.sh open_env &>/dev/null"
  if grep -qF "$line" "$USER_HOME/.bashrc"; then
    sed -i "\|$line|d" "$USER_HOME/.bashrc"; success "Auto-open désactivé"
  else
    echo "$line" >>"$USER_HOME/.bashrc"; success "Auto-open activé"
  fi
}

##############################################################################
# Interface menu (Whiptail) ou appel direct CLI                              
##############################################################################
cleanup_stale

if [[ ${1:-} == --menu ]]; then
  INTERACTIVE=1
  while true; do
    SECTION=$(whiptail --title "Coffre sécurisé" --menu "Section" 15 60 4 \
      Environnement "LUKS / ext4" \
      Cryptographie "GPG"         \
      SSH           "SSH"         \
      Quitter       "Quitter"     3>&1 1>&2 2>&3) || exit 0
    case $SECTION in
      Environnement)
        ACTION=$(whiptail --menu "Environnement" 20 60 6 \
                 install_env "Installer"  open_env  "Ouvrir" \
                 close_env   "Fermer"     delete_env "Supprimer" \
                 backup_env  "Backup"     status_env "Statut" 3>&1 1>&2 2>&3)
        [[ -n $ACTION ]] && $ACTION
        ;;
      Cryptographie)
        ACTION=$(whiptail --menu "GPG" 15 60 3 \
                 gpg_setup  "Créer une clé" \
                 gpg_import "Importer du coffre" \
                 gpg_export "Exporter vers coffre" 3>&1 1>&2 2>&3)
        [[ -n $ACTION ]] && $ACTION
        ;;
      SSH)
        ACTION=$(whiptail --menu "SSH" 20 60 8 \
                 ssh_create_template "Créer template via ~/.ssh/config" \
                 ssh_setup_alias     "Mettre en place l'alias evsh"     \
                 ssh_import_host     "Importer un Host existant"        \
                 ssh_delete          "Vider le vault SSH"               \
                 ssh_backup          "Backup du vault SSH"              \
                 restore_ssh_wallet  "Restaurer un backup"              \
                 auto_open_toggle    "Auto-open au login"               \
                 Retour             "Retour" 3>&1 1>&2 2>&3)
        [[ $ACTION != Retour ]] && $ACTION
        ;;
      Quitter) exit 0 ;;
    esac
  done
else
  FUNC="${1//-/_}"; shift || true
  if [[ $(type -t "$FUNC") == function ]]; then
    "$FUNC" "$@"
  else
    echo "Usage : sudo $0 --menu  ou  sudo $0 <fonction>" >&2; exit 1
  fi
fi
