#!/bin/bash
# Secure Environment toolbox

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs et logs ─────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
LOG="/tmp/env2.log"; : >"$LOG"
exec 3>&1
log(){ echo "[$(date +%T)] $*" >>"$LOG"; }
info(){ echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }
error(){ echo -e "${RED}$*${NC}" >&2; }

# ─── Pré-vérifications ───────────────────────────────────────────────────────
(( EUID==0 )) || { error "Relancez en root"; exit 1; }
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

if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi
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
  whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
  echo -e "\n— Derniers logs —" >&3
  tail -n 10 "$LOG" >&3
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
    fallocate -l "$SIZE" "$CONTAINER"
  elif command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none \
      | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    dd if=/dev/zero bs=1M count="$cnt" >"$CONTAINER"
    log "[!pv] pas de barre de progression"
  fi
  chmod 600 "$CONTAINER"
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
  mkdir -p "$SSH_DIR" "$GPG_DIR"
  log "[OK] Monté sur $MOUNT"
  success "✅ Install & mount OK"
  show_summary
}

open_env(){
  log "== OPEN ENV =="
  [[ ! -f "$CONTAINER" ]] && { log "[ER] Conteneur manquant"; show_summary; return; }
  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    read -s -p "Passphrase LUKS : " PASS; echo
    info "Ouverture LUKS…"
    printf '%s' "$PASS" \
      | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  fi
  mountpoint -q "$MOUNT" || mount "/dev/mapper/$MAPPER" "$MOUNT"
  mkdir -p "$SSH_DIR" "$GPG_DIR"
  log "[OK] Monté sur $MOUNT"
  success "✅ Environment ouvert et monté"
  show_summary
}

close_env(){
  log "== CLOSE ENV =="
  mountpoint -q "$MOUNT" && umount "$MOUNT" && log "[OK] Démonté"
  cryptsetup close "$MAPPER" && log "[OK] LUKS fermé"
  success "✅ Environment fermé"
  show_summary
}

delete_env(){
  log "== DELETE ENV =="
  mountpoint -q "$MOUNT" && umount "$MOUNT"
  cryptsetup close "$MAPPER" &>/dev/null||:
  rm -f "$CONTAINER" && log "[OK] Conteneur supprimé"
  rmdir "$MOUNT" 2>/dev/null||:
  success "✅ Environment supprimé"
  show_summary
}

backup_env(){
  log "== BACKUP ENV =="
  ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"
  log "[OK] Backup env+header"
  success "✅ Backup créé dans $BACKUP"
  show_summary
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>&1 || echo "mapper fermé" >>"$LOG"
  success "✅ Statut enregistré"
  show_summary
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
  log "[OK] Clé publique exportée"
  if whiptail --yesno "Exporter la clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" \
      >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
    log "[OK] Clé privée exportée"
  fi
  success "✅ GPG setup terminé"
  show_summary
}

gpg_import(){
  log "== GPG IMPORT =="
  ensure_env_open || return
  shopt -s nullglob
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "[OK] Import $f"
  done
  shopt -u nullglob
  success "✅ Import GPG terminé"
  show_summary
}

# ─── Partie III : SSH avancé ────────────────────────────────────────────────
ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  ensure_env_open || return
  [[ ! -f "$SSH_CONFIG" ]] && {
    whiptail --msgbox "Aucun ~/.ssh/config" 6 50
    log "[ER] Pas de ~/.ssh/config"
    return
  }
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
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi
  log "[OK] Template sshconf_$CH créé"
  whiptail --msgbox "Template '$CH' créé → $SSH_DIR/sshconf_$CH" 6 60
  success "✅ SSH template créé"
  show_summary
}


ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  ensure_env_open || return
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  log "[OK] Alias evsh créé"
  success "✅ Alias créé"
  show_summary
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
    cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")"
    sed -i "s|$idf|$SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi
  log "[OK] Host $CH importé"
  whiptail --msgbox "Host '$CH' importé" 6 50
  success "✅ SSH host importé"
  show_summary
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
  ssh -F "$SSH_DIR/$CH"
  log "[OK] Session SSH ($CH) terminée"
  success "✅ Session terminée"
}

ssh_delete(){
  log "== SSH DELETE =="
  ensure_env_open || return
  rm -rf "$SSH_DIR"/*
  whiptail --msgbox "Vault SSH vidé." 6 50
  log "[OK] Vault SSH vidé"
  success "✅ Vault SSH vidé"
  show_summary
}

ssh_backup(){
  log "== SSH BACKUP =="
  ensure_env_open || return
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
  whiptail --msgbox "Backup SSH → ssh_wallet_$ts.tar.gz" 6 60
  log "[OK] SSH backup $ts créé"
  success "✅ Backup SSH créé"
  show_summary
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
  success "✅ SSH wallet restauré"
  show_summary
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
  success "✅ Option mise à jour"
  show_summary
}

# ─── Menu principal ────────────────────────────────────────────────────────
cleanup_stale
if [[ "${1:-}" == "--menu" ]]; then
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
        if [[ -n "$ACTION" ]]; then
          $ACTION
          whiptail --msgbox "Opération terminée" 8 40
        fi
        ;;
      Cryptographie)
        ACTION=$(whiptail --title "GPG" --menu "Choisissez" 15 60 2 \
          gpg_setup  "Setup" \
          gpg_import "Import" \
          3>&1 1>&2 2>&3)
        if [[ -n "$ACTION" ]]; then
          $ACTION
          whiptail --msgbox "Opération terminée" 8 40
        fi
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
        if [[ -n "$ACTION" ]]; then
          $ACTION
          whiptail --msgbox "Opération terminée" 8 40
        fi
        ;;
      Quitter) exit 0 ;;
    esac
  done
else
  echo "Usage: $0 --menu"
fi
