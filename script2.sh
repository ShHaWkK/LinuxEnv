#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & log ───────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
USER_HOME="${SUDO_USER:+/home/$SUDO_USER}${SUDO_USER:-$HOME}"
LOG="$USER_HOME/secure_env.log" && : >"$LOG"
exec 3>&1
log(){ echo "[$(date +%T)] $*" >>"$LOG"; }
info(){ echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }
error(){ echo -e "${RED}$*${NC}" >&2; }

# ─── Vérifications ────────────────────────────────────────────────────────────
(( EUID==0 )) || { error "❌ Ce script doit être lancé en root (sudo)"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd lsblk df blkid pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "⛔ $cmd manquant"; exit 1; }
done

# ─── Variables globales ─────────────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$USER_HOME/env.img"
MAPPER="env_sec"
MOUNT="$USER_HOME/env_mount"
BACKUP="$USER_HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP="$BACKUP/ssh_wallets"
SSH_ALIAS_FILE="$SSH_DIR/alias_env.sh"
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"
INTERACTIVE=0

mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP"

spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}" ; sleep .1
  done
  printf "\r"
}

show_summary(){
  local msg="${1:-}"
  echo -e "\n— Logs récents —" >&3; tail -n 10 "$LOG" >&3
  (( INTERACTIVE )) && { whiptail --title "Résumé" --textbox "$LOG" 20 70; whiptail --msgbox "$msg" 8 50; }
}

cleanup(){
  mountpoint -q "$MOUNT" && { umount "$MOUNT"; log "[OK] Démonté $MOUNT"; }
  cryptsetup status "$MAPPER" &>/dev/null && { cryptsetup close "$MAPPER"; log "[OK] Fermé $MAPPER"; }
}

ensure_open(){
  mountpoint -q "$MOUNT" || open_env || return 1
}

# ─── PART I : LUKS/ext4 ────────────────────────────────────────────────────────

ask_pass(){
  read -p "Taille conteneur (5G) : " SIZE; SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmation    : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "❌ Passphrases différentes"; exit 1; }
}

install_env(){
  log "INSTALL ENV"; cleanup; ask_pass
  [[ -f $CONTAINER ]] && whiptail --yesno "Écraser $CONTAINER ?" 8 50 && rm -f "$CONTAINER" && log "Ancien conteneur supprimé"
  info "Création fichier…"
  ( fallocate -l "$SIZE" "$CONTAINER" || dd if=/dev/zero bs=1M count=${SIZE%G} of="$CONTAINER" ) & spinner $!
  chmod 600 "$CONTAINER"; chown root:root "$CONTAINER"; log "Conteneur prêt"
  info "Formatage LUKS…"
  printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=- 
  log "LUKS ouvert"
  info "Création ext4…"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!; log "ext4 formaté"
  mount "/dev/mapper/$MAPPER" "$MOUNT"; chmod -R go-rwx "$MOUNT"; chown root:root "$MOUNT"
  log "Monté sur $MOUNT"
  success "✅ install_env OK"; show_summary
}

open_env(){
  log "OPEN ENV"; cleanup
  [[ ! -f $CONTAINER ]] && { error "Pas de conteneur"; return; }
  cryptsetup status "$MAPPER" &>/dev/null || {
    read -s -p "Passphrase LUKS : " PASS; echo
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=- 
    log "LUKS ouvert"
  } && info "⚠️ LUKS déjà ouvert"
  mountpoint -q "$MOUNT" || {
    mount "/dev/mapper/$MAPPER" "$MOUNT"
    chmod -R go-rwx "$MOUNT"; chown root:root "$MOUNT"
    log "Monté"
  }
  success "✅ open_env OK"; show_summary
}

close_env(){
  log "CLOSE ENV"
  mountpoint -q "$MOUNT" && { umount "$MOUNT"; log "Démonté"; } || info "⚠️ Pas monté"
  cryptsetup status "$MAPPER" &>/dev/null && { cryptsetup close "$MAPPER"; log "Fermé"; } || info "⚠️ Déjà fermé"
  success "✅ close_env OK"; show_summary
}

delete_env(){
  log "DELETE ENV"; cleanup
  [[ ! -f $CONTAINER ]] && { error "Pas de conteneur"; return; }
  read -s -p "Confirmez passphrase : " DEL; echo
  printf '%s' "$DEL" | cryptsetup open --test-passphrase "$CONTAINER" --key-file=- \
    || { error "❌ Passphrase incorrecte"; return; }
  rm -f "$CONTAINER"; rmdir "$MOUNT" 2>/dev/null; log "Conteneur supprimé"
  success "✅ delete_env OK"; show_summary
}

status_env(){
  log "STATUS ENV"; lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>&1 || echo "mapper fermé" >>"$LOG"
  success "✅ status_env OK"; show_summary
}

backup_env(){
  log "BACKUP ENV"; cleanup
  mkdir -p "$BACKUP"; ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_${ts}.hdr"
  log "Backup env+header"; success "✅ backup_env OK"; show_summary
}

# ─── PART II : GPG ────────────────────────────────────────────────────────────

gpg_setup(){
  log "GPG SETUP"; open_env || return
  mkdir -p "$GPG_DIR"
  read -p "Nom        : " N; read -p "Email      : " E; read -p "Commentaire: " C
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
  gpg --export --armor "$key" >"$GPG_DIR/pub_${key}.gpg"
  chmod 644 "$GPG_DIR/pub_${key}.gpg"
  (( $?(whiptail --yesno "Exporter clé privée ?" 8 50; echo $?) == 0 )) && {
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/priv_${key}.gpg"
    chmod 600 "$GPG_DIR/priv_${key}.gpg"
  }
  success "✅ gpg_setup OK"; show_summary
}

gpg_import(){
  log "GPG IMPORT"; open_env || return
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do gpg --import "$f" && log "Import $f"; done
  shopt -u nullglob
  success "✅ gpg_import OK"; show_summary
}

# ─── PART III : SSH avancé ────────────────────────────────────────────────────

ssh_template(){
  log "SSH TEMPLATE"; open_env || return
  T="$SSH_DIR/template.conf"
  cat >"$T" <<EOF
# Exemple de template SSH
Host monserveur
    HostName example.com
    User $(whoami)
    Port 22
    IdentityFile $SSH_DIR/monserveur_id_rsa
EOF
  chmod 644 "$T"; log "Template créé $T"
  whiptail --msgbox "Template → $T" 8 50
  success "✅ ssh_template OK"; show_summary
}

ssh_alias(){
  log "SSH ALIAS"; open_env || return
  cat >"$SSH_ALIAS_FILE" <<EOF
alias evsh='ssh -F $SSH_DIR/sshconf_*'
EOF
  chmod 644 "$SSH_ALIAS_FILE"; ln -sf "$SSH_ALIAS_FILE" "$ALIAS_LINK"
  whiptail --msgbox "Alias evsh OK" 6 40
  success "✅ ssh_alias OK"; show_summary
}

ssh_import(){
  log "SSH IMPORT"; open_env || return
  [[ ! -f $SSH_CONFIG ]] && { error "Pas de ~/.ssh/config"; return; }
  mapfile -t H < <(grep '^Host ' "$SSH_CONFIG"|awk '{print$2}')
  (( ${#H[@]} )) || { error "Aucun host"; return; }
  C=$(whiptail --menu "Host → import" 15 60 ${#H[@]} "${H[@]/#//}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $C\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$C"
  chmod 600 "$SSH_DIR/sshconf_$C"
  IDF=$(awk '/IdentityFile/ {print $2;exit}' "$SSH_CONFIG")
  [[ -f $IDF ]] && {
    cp "$IDF" "$SSH_DIR/"; chmod 600 "$SSH_DIR/$(basename "$IDF")"
    [[ -f ${IDF}.pub ]] && cp "${IDF}.pub" "$SSH_DIR/"; chmod 644 "$SSH_DIR/$(basename "${IDF}.pub")"
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$IDF")|" "$SSH_DIR/sshconf_$C"
  }
  success "✅ ssh_import OK"; show_summary
}

ssh_start(){
  log "SSH START"; open_env || return
  mapfile -t F < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  (( ${#F[@]} )) || { error "Pas de configs"; return; }
  C=$(whiptail --menu "Lancer SSH" 15 60 ${#F[@]} "${F[@]/#//}" 3>&1 1>&2 2>&3) || return
  ssh -F "$C"
  success "✅ ssh_start OK"; show_summary
}

ssh_delete(){
  log "SSH DELETE"; open_env || return
  rm -rf "$SSH_DIR"/sshconf_* "$SSH_ALIAS_FILE"
  whiptail --msgbox "Vault SSH vidé" 6 40
  success "✅ ssh_delete OK"; show_summary
}

ssh_backup(){
  log "SSH BACKUP"; open_env || return
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP/ssh_vault_${ts}.tgz" -C "$SSH_DIR" .
  whiptail --msgbox "Backup → ssh_vault_${ts}.tgz" 6 40
  success "✅ ssh_backup OK"; show_summary
}

ssh_restore(){
  log "SSH RESTORE"; open_env || return
  mapfile -t B < <(ls "$SSH_BACKUP"/ssh_vault_*.tgz 2>/dev/null)
  (( ${#B[@]} )) || { error "Pas de backup"; return; }
  C=$(whiptail --menu "Restore SSH" 15 60 ${#B[@]} "${B[@]/#//}" 3>&1 1>&2 2>&3) || return
  tar xzf "$C" -C "$SSH_DIR"
  success "✅ ssh_restore OK"; show_summary
}

auto_open(){
  log "AUTO-OPEN"
  RS="secure_env.sh open_env"
  F="$USER_HOME/.bashrc"
  grep -q "$RS" "$F" && { sed -i "/$RS/d" "$F"; success "❌ auto-open OFF"; } \
    || { echo "$PWD/secure_env.sh open_env &>/dev/null" >>"$F"; success "✅ auto-open ON"; }
  show_summary
}

# ─── Menu & mode direct ───────────────────────────────────────────────────────
cleanup
if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1
  while true; do
    C=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
        Environnement "LUKS/ext4" \
        Cryptographie  "GPG"      \
        SSH             "SSH avancé" \
        Quitter        "Quitter" 3>&1 1>&2 2>&3) || exit 0
    case $C in
      Environnement)
        A=$(whiptail --title "LUKS/ext4" --menu "Opération" 20 60 6 \
           install_env "Installer" \
           open_env    "Ouvrir"    \
           close_env   "Fermer"    \
           delete_env  "Supprimer" \
           backup_env  "Backup"    \
           status_env  "Statut"    3>&1 1>&2 2>&3)
        [[ -n $A ]] && $A ;;
      Cryptographie)
        A=$(whiptail --title "GPG" --menu "Opération" 15 60 2 \
           gpg_setup  "Setup" \
           gpg_import "Import" 3>&1 1>&2 2>&3)
        [[ -n $A ]] && $A ;;
      SSH)
        A=$(whiptail --title "SSH avancé" --menu "Opération" 25 60 8 \
           ssh_template  "Créer template" \
           ssh_alias     "Configurer alias" \
           ssh_import    "Importer host" \
           ssh_start     "Lancer session" \
           ssh_delete    "Vider vault" \
           ssh_backup    "Backup vault" \
           ssh_restore   "Restore vault" \
           auto_open     "Toggle auto-open" 3>&1 1>&2 2>&3)
        [[ -n $A ]] && $A ;;
      Quitter) exit 0 ;;
    esac
  done
else
  ACT="${1:-}"; shift||:
  if type -t "$ACT" | grep -q function; then "$ACT" "$@"; else
    echo "Usage: $0 --menu | <action>" >&2; exit 1
  fi
fi
