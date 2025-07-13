#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & log ───────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
error(){ echo -e "${RED}$*${NC}" >&2; }
info(){ echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }

# ─── Droits root ──────────────────────────────────────────────────────────────
(( EUID==0 )) || { error "❌ Relancez en root"; exit 1; }

# ─── Détection de l'utilisateur non-root (via sudo) ────────────────────────────
if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER="$SUDO_USER"
else
  USER="$(whoami)"
fi
USER_HOME="/home/$USER"

# ─── Initialisation du log dans $USER_HOME ────────────────────────────────────
LOG="$USER_HOME/secure_env.log"
: > "$LOG"
exec 3>&1
log(){ echo "[$(date +%T)] $*" >>"$LOG"; }

# ─── Pré-vérifications ─────────────────────────────────────────────────────────
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd lsblk df blkid pv \
            whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "⛔ $cmd manquant"; exit 1; }
done

# ─── Variables globales ────────────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$USER_HOME/env.img"
MAPPER="env_sec"
MOUNT="$USER_HOME/env_mount"
BACKUP="$USER_HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"
ALIAS_FILE="$SSH_DIR/aliases_env"
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"

INTERACTIVE=0

mkdir -p "$MOUNT" "$BACKUP" "$SSH_BACKUP_DIR" "$SSH_DIR" "$GPG_DIR"

# ─── Spinner pour les opérations longues ──────────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

# ─── Affichage du résumé (+10 dernières lignes) ────────────────────────────────
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

# ─── Nettoyage de montages/mappers éventuels ──────────────────────────────────
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

# ─── PART I & IV : LUKS/ext4 ───────────────────────────────────────────────────
ask_pass(){
  read -p "Taille conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "❌ Passphrases différentes"; exit 1; }
}

install_env(){
  cleanup_stale; log "== INSTALL ENV =="
  ask_pass
  [[ -f "$CONTAINER" ]] && {
    whiptail --yesno "Le conteneur existe. Écraser ?" 8 50 || return
    rm -f "$CONTAINER"; log "[OK] Ancien conteneur supprimé"
  }
  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création du fichier ($SIZE)…"
  if command -v fallocate &>/dev/null; then
    fallocate -l "$SIZE" "$CONTAINER" & spinner $!
  else
    dd if=/dev/zero bs=1M count="$cnt" of="$CONTAINER" & spinner $!
  fi
  chmod 600 "$CONTAINER"; chown "$USER":"$USER" "$CONTAINER"
  log "[OK] conteneur créé ($SIZE)"

  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  log "[OK] LUKS formaté"

  info "Ouverture LUKS…"
  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  log "[OK] LUKS ouvert"

  info "Formatage ext4…"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  log "[OK] ext4 formaté"

  info "Montage…"
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"; chown -R "$USER":"$USER" "$MOUNT"
  log "[OK] Monté sur $MOUNT"

  success "✅ Install & mount OK"; show_summary "✅ Install terminé"
}

open_env(){
  cleanup_stale; log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] conteneur manquant"; show_summary "❌ Conteneur manquant"; return; }
  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -s -p "Passphrase LUKS : " PASS; echo
    info "Ouverture LUKS…"
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  else
    info "⚠️ LUKS déjà ouvert"; log "[!!] LUKS déjà ouvert"
  fi
  if ! mountpoint -q "$MOUNT"; then
    mount "/dev/mapper/$MAPPER" "$MOUNT"
    chmod -R go-rwx "$MOUNT"; chown -R "$USER":"$USER" "$MOUNT"
    log "[OK] Monté sur $MOUNT"
  else
    info "⚠️ Déjà monté"; log "[!!] Déjà monté"
  fi
  success "✅ Environment ouvert et monté"; show_summary
}

close_env(){
  log "== CLOSE ENV =="
  mountpoint -q "$MOUNT" && { umount "$MOUNT"; log "[OK] Démonté"; } || { info "⚠️ Pas monté"; log "[!!] Pas monté"; }
  cryptsetup status "$MAPPER" &>/dev/null && { cryptsetup close "$MAPPER"; log "[OK] LUKS fermé"; } \
    || { info "⚠️ Mapper déjà fermé"; log "[!!] Mapper fermé"; }
  success "✅ Environment fermé"; show_summary
}

delete_env(){
  log "== DELETE ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] pas de conteneur"; show_summary "❌ Aucun conteneur"; return; }
  read -s -p "Passphrase LUKS (conf) : " DP; echo
  if ! printf '%s' "$DP" | cryptsetup open --test-passphrase "$CONTAINER" --key-file=- &>/dev/null; then
    log "[ER] passphrase incorrecte"; show_summary "❌ Passphrase incorrecte"; return
  fi
  mountpoint -q "$MOUNT" && umount "$MOUNT"
  cryptsetup close "$MAPPER" &>/dev/null||:
  rm -f "$CONTAINER"; log "[OK] conteneur supprimé"
  rmdir "$MOUNT" 2>/dev/null||:
  success "✅ Environment supprimé"; show_summary
}

backup_env(){
  log "== BACKUP ENV =="
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  chown "$USER":"$USER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_${ts}.header"
  chown "$USER":"$USER" "$BACKUP/env_${ts}.header"
  success "✅ Backup créé → $BACKUP"; show_summary
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>&1 || echo "mapper fermé" >>"$LOG"
  success "✅ Statut enregistré"; show_summary
}

# ─── PART II : GPG ────────────────────────────────────────────────────────────
gpg_setup(){
  log "== GPG SETUP =="
  ensure_env_open || return
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
  local key; key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
  chown "$USER":"$USER" "$GPG_DIR"/public_*.gpg
  whiptail --yesno "Exporter la clé privée ?" 8 50 && \
    { gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"; chmod 600 "$GPG_DIR/private_${key}.gpg"; chown "$USER":"$USER" "$GPG_DIR/private_${key}.gpg"; }
  success "✅ GPG setup terminé"; show_summary
}

gpg_import(){
  log "== GPG IMPORT =="
  ensure_env_open || return
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] import $f"
  done
  shopt -u nullglob
  success "✅ Import GPG terminé"; show_summary
}

gpg_export(){
  log "== GPG EXPORT =="
  ensure_env_open || return
  mapfile -t keys < <(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}')
  [[ ${#keys[@]} -eq 0 ]] && { whiptail --msgbox "Aucune clé" 8 50; return; }
  tags=(); for k in "${keys[@]}"; do tags+=( "$k" "" ); done
  CH=$(whiptail --menu "Choisissez clé" 15 60 ${#keys[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  gpg --export --armor "$CH" >"$GPG_DIR/public_${CH}.gpg"
  chown "$USER":"$USER" "$GPG_DIR"/public_*.gpg
  whiptail --yesno "Exporter clé privée ?" 8 50 && \
    { gpg --export-secret-keys --armor "$CH" >"$GPG_DIR/private_${CH}.gpg"; chmod 600 "$GPG_DIR/private_${CH}.gpg"; chown "$USER":"$USER" "$GPG_DIR/private_${CH}.gpg"; }
  success "✅ Clé exportée"; show_summary
}

# ─── PART III : SSH avancé ───────────────────────────────────────────────────
ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  ensure_env_open || return
  if [[ ! -f "$SSH_CONFIG" ]]; then
    cat >"$SSH_DIR/ssh_template_example" <<'EOF'
# Exemple de configuration SSH
Host monserveur
    HostName example.com
    User monutilisateur
    Port 22
    IdentityFile /chemin/vers/la/clef
EOF
    chmod 600 "$SSH_DIR/ssh_template_example"; success "✅ Exemple créé → $SSH_DIR/ssh_template_example"; show_summary; return
  fi
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun host" 6 50; return; }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez host" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  idf=$(awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2;exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$SSH_DIR/"; chmod 600 "$SSH_DIR/$(basename "$idf")"; chown "$USER":"$USER" "$SSH_DIR/$(basename "$idf")"
    [[ -f "$idf.pub" ]] && { cp "$idf.pub" "$SSH_DIR/"; chmod 644 "$SSH_DIR/$(basename "$idf.pub")"; chown "$USER":"$USER" "$SSH_DIR/$(basename "$idf.pub")"; }
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi
  chmod 600 "$SSH_DIR/sshconf_$CH"; chown "$USER":"$USER" "$SSH_DIR/sshconf_$CH"
  success "✅ Template sshconf_$CH créé"; whiptail --msgbox "✅ -> $SSH_DIR/sshconf_$CH" 8 60; show_summary
}

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  ensure_env_open || return
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_FILE"
  chmod 644 "$ALIAS_FILE"; chown "$USER":"$USER" "$ALIAS_FILE"
  ln -sf "$ALIAS_FILE" "$ALIAS_LINK"
  success "✅ Alias evsh prêt (source $ALIAS_LINK)"; show_summary
}

ssh_import_host(){
  log "== SSH IMPORT HOST =="
  ensure_env_open || return
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun host" 6 50; return; }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez host" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  idf=$(awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2;exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$SSH_DIR/"; chmod 600 "$SSH_DIR/$(basename "$idf")"; chown "$USER":"$USER" "$SSH_DIR/$(basename "$idf")"
    [[ -f "$idf.pub" ]] && { cp "$idf.pub" "$SSH_DIR/"; chmod 644 "$SSH_DIR/$(basename "$idf.pub")"; chown "$USER":"$USER" "$SSH_DIR/$(basename "$idf.pub")"; }
    sed -i "s|$idf|$SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi
  chmod 600 "$SSH_DIR/sshconf_$CH"; chown "$USER":"$USER" "$SSH_DIR/sshconf_$CH"
  success "✅ Host $CH importé"; whiptail --msgbox "✅ SSH host importé" 6 50; show_summary
}

ssh_start(){
  log "== SSH START =="
  ensure_env_open || return
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  (( ${#cfgs[@]} )) || { whiptail --msgbox "Aucune config SSH" 6 50; return; }
  tags=(); for f in "${cfgs[@]}"; do
    h="${f##*_}"
    tags+=( "$h" "" )
  done
  CH=$(whiptail --menu "Choisissez config" 15 60 ${#cfgs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/sshconf_$CH" "$CH"
  success "✅ Session SSH $CH terminée"; show_summary
}

ssh_delete(){
  log "== SSH DELETE =="
  ensure_env_open || return
  rm -rf "$SSH_DIR"/*
  success "✅ Vault SSH vidé"; show_summary
}

ssh_backup(){
  log "== SSH BACKUP =="
  ensure_env_open || return
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  success "✅ Backup SSH créé → ssh_wallet_$ts.tar.gz"; show_summary
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  ensure_env_open || return
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  (( ${#bs[@]} )) || { whiptail --msgbox "Pas de backup SSH" 6 50; return; }
  tags=(); for b in "${bs[@]}"; do tags+=( "$(basename "$b")" "" ); done
  CH=$(whiptail --menu "Choisissez backup" 15 60 ${#bs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  success "✅ SSH wallet restauré → $CH"; show_summary
}

auto_open_toggle(){
  log "== AUTO-OPEN TOGGLE =="
  if grep -q "secure_env.sh open_env" "$USER_HOME/.bashrc"; then
    sed -i "/secure_env.sh open_env/d" "$USER_HOME/.bashrc"; success "✅ Auto-open désactivé"
  else
    echo "$PWD/secure_env.sh open_env &>/dev/null" >>"$USER_HOME/.bashrc"; success "✅ Auto-open activé"
  fi
  show_summary
}

# ─── Menu principal & mode direct ────────────────────────────────────────────
cleanup_stale
if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1
  while true; do
    SECTION=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      Environnement "LUKS/ext4" \
      Cryptographie   "GPG"     \
      SSH             "SSH"     \
      Quitter         "Quitter" 3>&1 1>&2 2>&3) || exit 0
    case $SECTION in
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
        ACTION=$(whiptail --title "SSH" --menu "Choisissez" 25 60 8 \
          ssh_create_template "Template SSH" \
          ssh_setup_alias     "Alias evsh"       \
          ssh_import_host     "Import host"      \
          ssh_start           "Start session"    \
          ssh_delete          "Vider vault"      \
          ssh_backup          "Backup vault"     \
          restore_ssh_wallet  "Restore vault"    \
          auto_open_toggle    "Auto-open"        3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      Quitter) exit 0 ;;
    esac
  done
else
  ACTION="${1:-}"
  [[ -n "$ACTION" && $(type -t "$ACTION") == "function" ]] \
    && { shift; "$ACTION" "$@"; } \
    || { echo "Usage: $0 --menu | <action>" >&2; exit 1; }
fi
