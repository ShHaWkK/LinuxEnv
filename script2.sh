#!/bin/bash
# Secure Environment toolbox

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs et logs ─────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
LOG="/tmp/env2.log"
exec 3>&1
log(){ echo "[$(date +%T)] $*" >>"$LOG"; }
info(){ echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }
error(){ echo -e "${RED}$*${NC}" >&2; }

# ─── Pré-vérifications ───────────────────────────────────────────────────────
(( EUID==0 )) || { error "Relancez en root"; exit 1; }
: >"$LOG"
for cmd in cryptsetup mkfs.ext4 mount umount fallocate lsblk df blkid pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "$cmd manquant"; exit 1; }
done

# ─── Variables globales ──────────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
MAPPER="env_sec"
MOUNT="$HOME/env_mount"
BACKUP="$HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"
ALIAS_LINK="$HOME/.aliases_env"
ALIAS_FILE="$SSH_DIR/aliases_env"

# 0=non-interactive, 1=menu
INTERACTIVE=0

if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi
OWNER="${SUDO_USER:-root}"
SSH_CONFIG="$USER_HOME/.ssh/config"

mkdir -p "$MOUNT" "$BACKUP" "$SSH_BACKUP_DIR"

# ─── Spinner ─────────────────────────────────────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

# ─── Affichage résumé ────────────────────────────────────────────────────────
show_summary(){
  local msg="${1:-}"
  if [[ ${INTERACTIVE:-0} -eq 1 ]]; then
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

# ─── Partie I & IV : Environnement LUKS/ext4 ─────────────────────────────────
ask_pass(){
  read -p "Taille conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "Passphrases différentes"; exit 1; }
}

install_env(){
  cleanup_stale
  log "== INSTALL ENV =="
  ask_pass

  if [[ -f "$CONTAINER" ]]; then
    if whiptail --yesno "Le conteneur existe déjà. Écraser ?" 8 50; then
      rm -f "$CONTAINER"
      log "[OK] Ancien conteneur supprimé"
    else
      return
    fi
  fi

  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création du fichier ($SIZE)…"
  if command -v fallocate &>/dev/null; then
    fallocate -l "$SIZE" "$CONTAINER" &
    spinner $!
  elif command -v pv &>/dev/null; then
    (dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER") &
    spinner $!
  else
    dd if=/dev/zero bs=1M count="$cnt" of="$CONTAINER" &
    spinner $!
    log "[!pv] pas de barre de progression"
  fi
  chmod 600 "$CONTAINER"
  chown "$OWNER":"$OWNER" "$CONTAINER"
  ls -l "$CONTAINER" >>"$LOG"
  log "[OK] Fichier conteneur créé ($SIZE)"

  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  log "[OK] LUKS formaté"

  info "Ouverture LUKS…"
  printf '%s' "$PASS" \
    | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  log "[OK] LUKS ouvert"

  info "Formatage ext4…"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  log "[OK] ext4 formaté"

  info "Montage…"
  mountpoint -q "$MOUNT" || mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"
  chown -R "$OWNER":"$OWNER" "$MOUNT"
  mkdir -p "$SSH_DIR" "$GPG_DIR"
  log "[OK] Monté sur $MOUNT"
  local msg="✅ Install & mount OK"
  success "$msg"
  show_summary "$msg"
}

open_env(){
  log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] Conteneur manquant"; show_summary "❌ Conteneur manquant"; return; }
  ls -l "$CONTAINER" >>"$LOG"
  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -s -p "Passphrase LUKS : " PASS; echo
    info "Ouverture LUKS…"
    printf '%s' "$PASS" \
      | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  fi
  mountpoint -q "$MOUNT" || mount "/dev/mapper/$MAPPER" "$MOUNT"
  chmod -R go-rwx "$MOUNT"
  chown -R "$OWNER":"$OWNER" "$MOUNT"
  mkdir -p "$SSH_DIR" "$GPG_DIR"
  log "[OK] Monté sur $MOUNT"
  cryptsetup status "$MAPPER" >>"$LOG"
  local msg="✅ Environment ouvert et monté"
  success "$msg"
  show_summary "$msg"
}

close_env(){
  log "== CLOSE ENV =="
  mountpoint -q "$MOUNT" && umount "$MOUNT" && log "[OK] Démonté"
  cryptsetup close "$MAPPER" && log "[OK] LUKS fermé"
  local msg="✅ Environment fermé"
  success "$msg"
  show_summary "$msg"
}

delete_env(){
  log "== DELETE ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] Conteneur introuvable"; show_summary "❌ Conteneur absent"; return; }
  read -s -p "Passphrase LUKS (confirmation) : " DEL_PASS; echo
  if ! printf '%s' "$DEL_PASS" | cryptsetup open --test-passphrase "$CONTAINER" --key-file=- >/dev/null 2>&1; then
    log "[ER] Passphrase incorrecte"
    show_summary "❌ Passphrase incorrecte"
    return
  fi
  mountpoint -q "$MOUNT" && umount "$MOUNT"
  cryptsetup close "$MAPPER" &>/dev/null||:
  ls -l "$CONTAINER" >>"$LOG"
  rm -f "$CONTAINER" && log "[OK] Conteneur supprimé"
  rmdir "$MOUNT" 2>/dev/null||:
  ls -l "$CONTAINER" 2>>"$LOG" || log "[OK] Fichier supprimé"
  local msg="✅ Environment supprimé"
  success "$msg"
  show_summary "$msg"
}

backup_env(){
  log "== BACKUP ENV =="
  ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  chown "$OWNER":"$OWNER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"
  chown "$OWNER":"$OWNER" "$BACKUP/env_${ts}.header"
  log "[OK] Backup env+header"
  local msg="✅ Backup créé dans $BACKUP"
  success "$msg"
  show_summary "$msg"
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>&1 || echo "mapper fermé" >>"$LOG"
  local msg="✅ Statut enregistré"
  success "$msg"
  show_summary "$msg"
}

# ─── Partie II : GPG automatisé ─────────────────────────────────────────────
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
  local key=$(gpg --list-secret-keys --with-colons \
    | awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
  chown "$OWNER":"$OWNER" "$GPG_DIR/public_${key}.gpg"
  log "[OK] Clé publique exportée"
  if whiptail --yesno "Exporter la clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" \
      >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
    chown "$OWNER":"$OWNER" "$GPG_DIR/private_${key}.gpg"
    log "[OK] Clé privée exportée"
  fi
  local msg="✅ GPG setup terminé"
  success "$msg"
  show_summary "$msg"
}

gpg_import(){
  log "== GPG IMPORT =="
  ensure_env_open || return
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] Import $f"
  done
  shopt -u nullglob
  local msg="✅ Import GPG terminé"
  success "$msg"
  show_summary "$msg"
}

# ─── Partie III : SSH avancé ────────────────────────────────────────────────
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
    chmod 600 "$SSH_DIR/ssh_template_example"
    whiptail --msgbox "Exemple créé : $SSH_DIR/ssh_template_example" 8 60
    log "[OK] Exemple de template créé"
    local msg="✅ Exemple de template créé"
    success "$msg"
    show_summary "$msg"
    return
  fi
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && {
    whiptail --msgbox "Aucun host trouvé" 6 50
    log "[ER] Pas de host"
    return
  }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --title "ssh-create-template" \
    --menu "Choisissez un host" 15 60 ${#hosts[@]} \
    "${tags[@]}" \
    3>&1 1>&2 2>&3) || return
  awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  idf=$(awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2; exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")" && chown "$OWNER":"$OWNER" "$SSH_DIR/$(basename "$idf")"
    [[ -f "$idf.pub" ]] && cp "$idf.pub" "$SSH_DIR/" && chmod 644 "$SSH_DIR/$(basename "$idf.pub")" && chown "$OWNER":"$OWNER" "$SSH_DIR/$(basename "$idf.pub")"
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi
  chmod 600 "$SSH_DIR/sshconf_$CH"
  chown "$OWNER":"$OWNER" "$SSH_DIR/sshconf_$CH"
  log "[OK] Template sshconf_$CH créé"
  local msg="✅ SSH template créé : $CH"
  whiptail --msgbox "Template '$CH' créé → $SSH_DIR/sshconf_$CH" 6 60
  success "$msg"
  show_summary "$msg"
}


ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  ensure_env_open || return
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_FILE"
  chmod 644 "$ALIAS_FILE"
  chown "$OWNER":"$OWNER" "$ALIAS_FILE"
  ln -sf "$ALIAS_FILE" "$ALIAS_LINK"
  log "[OK] Alias evsh créé et lien $ALIAS_LINK"
  local msg="✅ Alias créé"
  success "$msg"
  show_summary "$msg"
}

ssh_import_host(){
  log "== SSH IMPORT HOST =="
  ensure_env_open || return
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; log "[ER] pas de config"; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && { whiptail --msgbox "Aucun host" 6 50; log "[ER] aucun host"; return; }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez host" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  idf=$(awk "/^Host $CH$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2; exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")" && chown "$OWNER":"$OWNER" "$SSH_DIR/$(basename "$idf")"
    [[ -f "$idf.pub" ]] && cp "$idf.pub" "$SSH_DIR/" && chmod 644 "$SSH_DIR/$(basename "$idf.pub")" && chown "$OWNER":"$OWNER" "$SSH_DIR/$(basename "$idf.pub")"
    sed -i "s|$idf|$SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi
  chmod 600 "$SSH_DIR/sshconf_$CH"
  chown "$OWNER":"$OWNER" "$SSH_DIR/sshconf_$CH"
  log "[OK] Host $CH importé"
  whiptail --msgbox "Host '$CH' importé" 6 50
  local msg="✅ SSH host importé : $CH"
  success "$msg"
  show_summary "$msg"
}

ssh_start(){
  log "== SSH START =="
  ensure_env_open || return
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  [[ ${#cfgs[@]} -eq 0 ]] && {
    whiptail --msgbox "Aucune config SSH trouvée" 6 50
    log "[ER] Pas de sshconf_"
    return
  }
  tags=(); for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" "" ); done
  CH=$(whiptail --title "ssh-start" \
    --menu "Choisissez configuration" 15 60 ${#cfgs[@]} \
    "${tags[@]}" \
    3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$CH" "$CH"
  log "[OK] Session SSH ($CH) terminée"
  local msg="✅ Session terminée"
  success "$msg"
  show_summary "$msg"
}

ssh_delete(){
  log "== SSH DELETE =="
  ensure_env_open || return
  rm -rf "$SSH_DIR"/*
  whiptail --msgbox "Vault SSH vidé." 6 50
  log "[OK] Vault SSH vidé"
  local msg="✅ Vault SSH vidé"
  success "$msg"
  show_summary "$msg"
}

ssh_backup(){
  log "== SSH BACKUP =="
  ensure_env_open || return
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  whiptail --msgbox "Backup SSH → ssh_wallet_$ts.tar.gz" 6 60
  log "[OK] SSH backup $ts créé"
  local msg="✅ Backup SSH créé"
  success "$msg"
  show_summary "$msg"
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  ensure_env_open || return
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  [[ ${#bs[@]} -eq 0 ]] && {
    whiptail --msgbox "Aucune sauvegarde SSH" 6 50
    log "[ER] Pas de SSH backup"
    return
  }
  tags=(); for b in "${bs[@]}"; do tags+=( "$(basename "$b")" "" ); done
  CH=$(whiptail --title "restore-ssh-wallet" \
    --menu "Choisissez backup" 15 60 ${#bs[@]} \
    "${tags[@]}" \
    3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  whiptail --msgbox "Backup restauré : $CH" 6 60
  log "[OK] SSH wallet restauré ($CH)"
  local msg="✅ SSH wallet restauré"
  success "$msg"
  show_summary "$msg"
}

auto_open_toggle(){
  log "== AUTO-OPEN TOGGLE =="
  if grep -q "secure_env.sh open_env" "$HOME/.bashrc"; then
    sed -i "/secure_env.sh open_env/d" "$HOME/.bashrc"
    log "[OK] Auto-open OFF"
  else
    echo "$PWD/secure_env.sh open_env &>/dev/null" >>"$HOME/.bashrc"
    log "[OK] Auto-open ON"
  fi
  local msg="✅ Option mise à jour"
  success "$msg"
  show_summary "$msg"
}

# ─── Menu principal ────────────────────────────────────────────────────────
cleanup_stale
if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1
  while :; do
    SECTION=$(whiptail --title "Secure Env" --menu "Menu" 15 60 4 \
      Environnement "Environnement" \
      Cryptographie "Cryptographie" \
      SSH "SSH" \
      Quitter "Quitter" \
      3>&1 1>&2 2>&3) || exit

    case $SECTION in
      Environnement)
        ACTION=$(whiptail --title "Environnement" --menu "Choisissez" 20 60 6 \
          install_env "Installer" \
          open_env    "Ouvrir"    \
          close_env   "Fermer"    \
          delete_env  "Supprimer" \
          backup_env  "Backup"    \
          status_env  "Statut"    \
          3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION
        ;;
      Cryptographie)
        ACTION=$(whiptail --title "GPG" --menu "Choisissez" 15 60 2 \
          gpg_setup  "Setup" \
          gpg_import "Import" \
          3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION
        ;;
      SSH)
        ACTION=$(whiptail --title "SSH" --menu "Choisissez" 25 60 8 \
          ssh_create_template "ssh-create-template" \
          ssh_setup_alias     "ssh-setup-alias"     \
          ssh_import_host     "ssh-import-host"     \
          ssh_start           "ssh-start"           \
          ssh_delete          "ssh-delete"          \
          ssh_backup          "ssh-backup"          \
          restore_ssh_wallet  "restore-ssh-wallet"  \
          auto_open_toggle    "auto-open"           \
          3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION
        ;;
      Quitter) exit 0 ;;
    esac
  done
else
  ACTION="${1:-}"
  if [[ -n "$ACTION" && $(type -t "$ACTION") == "function" ]]; then
    shift
    "$ACTION" "$@"
  else
    echo "Usage: $0 --menu|<action>" >&2
    exit 1
  fi
fi
