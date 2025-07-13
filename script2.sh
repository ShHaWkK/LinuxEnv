#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail
set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & log ───────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
error(){ echo -e "${RED}$*${NC}" >&2; }
info (){ echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }

# ─── Détection de l’utilisateur non-root ──────────────────────────────────────
if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
  OWNER="$SUDO_USER"
else
  USER_HOME="$HOME"
  OWNER="$(id -un)"
fi

# ─── Initialisation du log dans $USER_HOME ────────────────────────────────────
LOG="$USER_HOME/secure_env.log"
mkdir -p "$(dirname "$LOG")"
: >"$LOG"
chmod 600 "$LOG"
chown "$OWNER":"$OWNER" "$LOG"
exec 3>&1

log(){ echo "[$(date +%T)] $*" >>"$LOG"; }

# ─── Vérifications préalables ─────────────────────────────────────────────────
(( EUID==0 )) || { error "❌ Relancez en root !"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv \
           whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "⛔ $cmd manquant"; exit 1; }
done

# ─── Variables globales ───────────────────────────────────────────────────────
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

# ─── Petite animation pour les tâches longues ─────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" &>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"; sleep .1
  done
  printf "\r"
}

# ─── Affichage du résumé + derniers logs via Whiptail ──────────────────────────
show_summary(){
  local msg="${1:-}"
  if [[ "$INTERACTIVE" -eq 1 ]]; then
    whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
    [[ -n "$msg" ]] && whiptail --msgbox "$msg"  8 50
  fi
  echo -e "\n— Derniers logs —" >&3
  tail -n 10 "$LOG" >&3
  [[ -n "$msg" ]] && echo "$msg" >&3
}

# ─── Nettoyage des mappers/mounts restés ouverts ───────────────────────────────
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

# ─── PART I & IV : Environnement LUKS/ext4 ────────────────────────────────────
ask_pass(){
  read -p "Taille du conteneur (ex:5G) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "❌ Passphrases différentes"; exit 1; }
}

install_env(){
  cleanup_stale; log "== INSTALL ENV =="
  ask_pass
  [[ -f "$CONTAINER" ]] && \
    { whiptail --yesno "Le conteneur existe. Écraser ?" 8 50 || return; rm -f "$CONTAINER"; log "[OK] conteneur supprimé"; }

  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création du fichier ($SIZE)…"
  fallocate -l "$SIZE" "$CONTAINER" & spinner $!
  chmod 600 "$CONTAINER"; chown "$OWNER":"$OWNER" "$CONTAINER"; log "[OK] conteneur créé"

  info "Formatage LUKS (taper YES)…"
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
  mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"; chown -R "$OWNER":"$OWNER" "$MOUNT"
  log "[OK] Monté sur $MOUNT"

  success "✅ Install & mount OK"; show_summary
}

open_env(){
  cleanup_stale; log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] conteneur manquant"; show_summary "❌ Conteneur manquant"; return; }
  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -s -p "Passphrase LUKS : " PASS; echo
    info "Ouverture LUKS…"
    printf '%s' "$PASS" \
      | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  else
    info "⚠️ LUKS déjà ouvert"; log "[!!] déjà ouvert"
  fi

  if ! mountpoint -q "$MOUNT"; then
    mount "/dev/mapper/$MAPPER" "$MOUNT"
    chmod -R go-rwx "$MOUNT"; chown -R "$OWNER":"$OWNER" "$MOUNT"
    log "[OK] Monté sur $MOUNT"
  else
    info "⚠️ déjà monté"; log "[!!] déjà monté"
  fi

  success "✅ Environment ouvert et monté"; show_summary
}

close_env(){
  log "== CLOSE ENV =="
  mountpoint -q "$MOUNT" && { umount "$MOUNT"; log "[OK] démonté"; } || info "⚠️ pas monté"
  cryptsetup status "$MAPPER" &>/dev/null && { cryptsetup close "$MAPPER"; log "[OK] LUKS fermé"; } \
    || info "⚠️ déjà fermé"
  success "✅ Environment fermé"; show_summary
}

delete_env(){
  log "== DELETE ENV =="
  close_env
  [[ -f "$CONTAINER" ]] && { rm -f "$CONTAINER"; log "[OK] conteneur supprimé"; }
  rmdir "$MOUNT" &>/dev/null || :
  success "✅ Environment supprimé"; show_summary
}

backup_env(){
  log "== BACKUP ENV =="
  ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"
  log "[OK] Backup env+header"
  success "✅ Backup créé dans $BACKUP"; show_summary
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
  shopt -s nullglob
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
  key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
  chmod 644 "$GPG_DIR/public_${key}.gpg"; chown "$OWNER":"$OWNER" "$GPG_DIR/public_${key}.gpg"
  log "[OK] clé publique exportée"
  if whiptail --yesno "Exporter la clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"; chown "$OWNER":"$OWNER" "$GPG_DIR/private_${key}.gpg"
    log "[OK] clé privée exportée"
  fi
  success "✅ GPG setup terminé"; show_summary
}

gpg_import(){
  log "== GPG IMPORT =="
  ensure_env_open || return
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] import $f"
  done
  success "✅ Import GPG terminé"; show_summary
}

gpg_export(){
  log "== GPG EXPORT =="
  ensure_env_open || return
  mapfile -t keys < <(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5}')
  (( ${#keys[@]} )) || { whiptail --msgbox "Aucune clé disponible" 8 50; return; }
  tags=(); for k in "${keys[@]}"; do tags+=( "$k" "" ); done
  CH=$(whiptail --menu "Choisissez la clé" 15 60 ${#keys[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  gpg --export --armor "$CH" >"$GPG_DIR/public_${CH}.gpg"
  chmod 644 "$GPG_DIR/public_${CH}.gpg"; chown "$OWNER":"$OWNER" "$GPG_DIR/public_${CH}.gpg"
  if whiptail --yesno "Exporter la clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$CH" >"$GPG_DIR/private_${CH}.gpg"
    chmod 600 "$GPG_DIR/private_${CH}.gpg"; chown "$OWNER":"$OWNER" "$GPG_DIR/private_${CH}.gpg"
  fi
  success "✅ Clé exportée"; show_summary
}

# ─── PART III : SSH ──────────────────────────────────────────────────────────
ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  ensure_env_open || return
  cat >"$SSH_DIR/ssh_template.conf" <<'EOF'
# Exemple de configuration SSH
Host monserveur
    HostName example.com
    User monutilisateur
    Port 22
    IdentityFile /chemin/vers/la/clef
EOF
  chmod 600 "$SSH_DIR/ssh_template.conf"; chown "$OWNER":"$OWNER" "$SSH_DIR/ssh_template.conf"
  whiptail --msgbox "Template créé : $SSH_DIR/ssh_template.conf" 8 60
  success "✅ Template SSH créé"; show_summary
}

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  ensure_env_open || return
  echo "alias evsh=\"ssh -F $SSH_DIR/sshconf_*\"" >"$ALIAS_FILE"
  chmod 644 "$ALIAS_FILE"; chown "$OWNER":"$OWNER" "$ALIAS_FILE"
  ln -sf "$ALIAS_FILE" "$ALIAS_LINK"
  whiptail --msgbox "Alias installé via $ALIAS_LINK" 6 60
  success "✅ Alias evsh prêt"; show_summary
}

ssh_import_host(){
  log "== SSH IMPORT HOST =="
  ensure_env_open || return
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; return; }
  mapfile -t hosts < <(awk '/^Host /{print $2}' "$SSH_CONFIG")
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun host trouvé" 6 50; return; }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez host" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return

  # copie du bloc config
  awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  chmod 600 "$SSH_DIR/sshconf_$CH"; chown "$OWNER":"$OWNER" "$SSH_DIR/sshconf_$CH"

  # extraction et copie de la clé
  keyfile=$(awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG" \
             | awk '/IdentityFile/ {print $2; exit}')
  if [[ -f "$keyfile" ]]; then
    cp "$keyfile" "$SSH_DIR/"; chmod 600 "$SSH_DIR/$(basename "$keyfile")"
    [[ -f "${keyfile}.pub" ]] && cp "${keyfile}.pub" "$SSH_DIR/" && chmod 644 "$SSH_DIR/$(basename "${keyfile}.pub")"
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$keyfile")|" "$SSH_DIR/sshconf_$CH"
  fi

  success "✅ Host $CH importé"; show_summary
}

ssh_start(){
  log "== SSH START =="
  ensure_env_open || return
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  (( ${#cfgs[@]} )) || { whiptail --msgbox "Aucune config SSH dans coffre" 6 50; return; }
  tags=(); for f in "${cfgs[@]}"; do host=${f##*/sshconf_}; tags+=( "$host" "" ); done
  CH=$(whiptail --menu "Choisissez config" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/sshconf_$CH" "$CH"
  success "✅ Session SSH $CH terminée"; show_summary
}

ssh_delete(){
  log "== SSH DELETE =="
  ensure_env_open || return
  rm -rf "$SSH_DIR"/sshconf_* "$SSH_DIR"/aliases_env "$SSH_DIR"/ssh_template.conf "$SSH_DIR"/*.{pub,}
  whiptail --msgbox "Vault SSH vidé." 6 50
  success "✅ Vault SSH vidé"; show_summary
}

ssh_backup(){
  log "== SSH BACKUP =="
  ensure_env_open || return
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_${ts}.tar.gz" -C "$SSH_DIR" .
  chown "$OWNER":"$OWNER" "$SSH_BACKUP_DIR/ssh_wallet_${ts}.tar.gz"
  whiptail --msgbox "Backup créé : $SSH_BACKUP_DIR/ssh_wallet_${ts}.tar.gz" 6 60
  success "✅ SSH backup créé"; show_summary
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  ensure_env_open || return
  mapfile -t backups < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  (( ${#backups[@]} )) || { whiptail --msgbox "Aucune sauvegarde SSH" 6 50; return; }
  tags=(); for b in "${backups[@]}"; do tags+=( "$(basename "$b")" "" ); done
  CH=$(whiptail --menu "Choisissez backup" 15 60 ${#backups[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  chown -R "$OWNER":"$OWNER" "$SSH_DIR"
  success "✅ SSH wallet restauré"; show_summary
}

auto_open_toggle(){
  log "== AUTO-OPEN TOGGLE =="
  MARK="secure_env.sh open_env"
  if grep -qF "$MARK" "$USER_HOME/.bashrc"; then
    sed -i "\|$MARK|d" "$USER_HOME/.bashrc"
    success "✅ Auto-open désactivé"
  else
    echo "$PWD/secure_env.sh open_env &>/dev/null" >>"$USER_HOME/.bashrc"
    success "✅ Auto-open activé"
  fi
  show_summary
}

# ─── Menu principal & mode direct ─────────────────────────────────────────────
cleanup_stale
if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1
  while true; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
      Environnement   "LUKS/ext4" \
      Cryptographie   "GPG"      \
      SSH             "SSH"      \
      Quitter         "Quitter" 3>&1 1>&2 2>&3) || exit 0
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
        ACTION=$(whiptail --title "SSH" --menu "Choisissez" 25 60 8 \
          ssh_create_template "Template SSH"  \
          ssh_setup_alias     "Alias evsh"       \
          ssh_import_host     "Import host"      \
          ssh_start           "Lancer SSH"       \
          ssh_delete          "Purger vault"     \
          ssh_backup          "Backup vault"     \
          restore_ssh_wallet  "Restaure backup"  \
          auto_open_toggle    "Auto-open"        3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      Quitter) exit 0 ;;
    esac
  done
else
  ACTION="${1:-}"
  if [[ -n "$ACTION" && $(type -t "$ACTION") == "function" ]]; then
    shift; "$ACTION" "$@"
  else
    echo "Usage: $0 --menu | <action>" >&2; exit 1
  fi
fi
