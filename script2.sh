#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail
set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & Log ─────────────────────────────────────────────────────────
RED='\e[31m'   ; GREEN='\e[32m' ; BLUE='\e[34m'  ; NC='\e[0m'
LOG="/tmp/secure_env.log"
: >"$LOG"
log()    { echo "[$(date +%T)] $*" >>"$LOG"; }
info()   { echo -e "${BLUE}$*${NC}"; }
success(){ echo -e "${GREEN}$*${NC}"; }
error()  { echo -e "${RED}$*${NC}" >&2; }

# ─── Variables globales ────────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$HOME/env.img"
MAPPER="env_sec"
MOUNT="$HOME/env_mount"
BACKUP="$HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP="$BACKUP/ssh_wallets"
ALIAS_LINK="$HOME/.aliases_env"

# ─── Pré-vérifications ──────────────────────────────────────────────────────
(( EUID==0 )) || { error "Relancez en root !"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "⛔ $cmd manquant"; exit 1; }
done

# ─── Création dossiers ──────────────────────────────────────────────────────
mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP"

# ─── Spinner pour tâches longues ────────────────────────────────────────────
spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"; sleep .1
  done
  printf "\r"
}

# ─── Nettoyage stale mounts/mappers ─────────────────────────────────────────
cleanup(){
  if mountpoint -q "$MOUNT"; then umount "$MOUNT" && log "🔸 Démonté $MOUNT"; fi
  if cryptsetup status "$MAPPER" &>/dev/null; then
    cryptsetup close "$MAPPER" && log "🔸 Fermé /dev/mapper/$MAPPER"
  fi
}

# ─── Affichage résumé (log) ─────────────────────────────────────────────────
show_summary(){
  whiptail --title "Résumé Opération" --textbox "$LOG" 20 70
}

# ─── Helpers de check ───────────────────────────────────────────────────────
ensure_open(){
  if [[ ! -f "$CONTAINER" ]]; then
    error "📦 Conteneur absent"; return 1
  fi
  if ! cryptsetup status "$MAPPER" &>/dev/null; then
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=- && log "🔸 LUKS ouvert"
  fi
  if ! mountpoint -q "$MOUNT"; then
    mount /dev/mapper/"$MAPPER" "$MOUNT" && chmod -R go-rwx "$MOUNT" && log "🔸 Monté $MOUNT"
  fi
}

# ─── Part I & IV : Environnement LUKS + ext4 ────────────────────────────────
ask_pass(){
  read -p "Taille du conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "❌ Passphrases différentes"; exit 1; }
}

install_env(){
  cleanup; log "===== INSTALL ENVIRONMENT ====="
  ask_pass
  if [[ -f "$CONTAINER" ]]; then
    if whiptail --yesno "Le conteneur existe. Écraser ?" 8 50; then
      rm -f "$CONTAINER" && log "🔸 Ancien conteneur supprimé"
    else return; fi
  fi
  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création du fichier ($SIZE)…"
  if command -v pv &>/dev/null; then
    dd if=/dev/zero bs=1M count="$cnt" status=none \
      | pv -s $((cnt*1024*1024)) >"$CONTAINER"
  else
    dd if=/dev/zero bs=1M count="$cnt" of="$CONTAINER"
    log "⚠️ pv absent, pas de barre de progression"
  fi
  chmod 600 "$CONTAINER" && log "🔸 $CONTAINER créé"
  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" \
    | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $! && log "🔸 LUKS formaté"
  info "Ouverture LUKS…"
  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=- && log "🔸 /dev/mapper/$MAPPER"
  info "Formatage ext4…"
  mkfs.ext4 /dev/mapper/"$MAPPER" & spinner $! && log "🔸 ext4 créé"
  info "Montage…"
  mount /dev/mapper/"$MAPPER" "$MOUNT" && chmod -R go-rwx "$MOUNT" && log "🔸 Monté $MOUNT"
  success "✅ Install & mount OK"; show_summary
}

open_env(){
  log "===== OPEN ENVIRONMENT ====="
  read -s -p "Passphrase LUKS : " PASS; echo
  cleanup || true
  ensure_open || { show_summary; return; }
  success "✅ Environment ouvert et monté"; show_summary
}

close_env(){
  log "===== CLOSE ENVIRONMENT ====="
  umount "$MOUNT" &>/dev/null && log "🔸 Démonté $MOUNT"
  cryptsetup close "$MAPPER" && log "🔸 Fermé $MAPPER"
  success "✅ Environment fermé"; show_summary
}

delete_env(){
  log "===== DELETE ENVIRONMENT ====="
  umount "$MOUNT" &>/dev/null||:
  cryptsetup close "$MAPPER" &>/dev/null||:
  rm -f "$CONTAINER" && log "🔸 $CONTAINER supprimé"
  rmdir "$MOUNT" 2>/dev/null||:
  success "✅ Environment supprimé"; show_summary
}

backup_env(){
  log "===== BACKUP ENVIRONMENT ====="
  ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" \
    --header-backup-file "$BACKUP/env_${ts}.header"
  success "✅ Backup → $BACKUP/env_${ts}.img + .header"; show_summary
}

status_env(){
  log "===== STATUS ENVIRONMENT ====="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" >>"$LOG" 2>&1 || echo "mapper fermé" >>"$LOG"
  show_summary
}

# ─── Part II : GPG ───────────────────────────────────────────────────────────
gpg_setup(){
  log "===== GPG SETUP ====="
  ensure_open || { whiptail --msgbox "Environnement non monté" 8 50; return; }
  mkdir -p "$GPG_DIR"
  read -p "Nom        : " N
  read -p "Email      : " E
  read -p "Commentaire: " C
  cat >gpg-batch<<EOF
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
  key=$(gpg --list-secret-keys --with-colons|awk -F: '/^sec/ {print $5;exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
  log "🔸 Clé publique exportée"
  if whiptail --yesno "Exporter la clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
    log "🔸 Clé privée exportée"
  fi
  success "✅ GPG setup terminé → fichiers dans $GPG_DIR"; show_summary
}

gpg_import(){
  log "===== GPG IMPORT ====="
  ensure_open || { whiptail --msgbox "Environnement non monté" 8 50; return; }
  for f in "$GPG_DIR"/*.gpg; do
    gpg --import "$f" && log "🔸 Importé $f"
  done
  success "✅ Import GPG terminé depuis → $GPG_DIR"; show_summary
}

# ─── Part III : SSH ──────────────────────────────────────────────────────────
ssh_create_template(){
  log "===== SSH CREATE TEMPLATE ====="
  ensure_open || { whiptail --msgbox "Environnement non monté" 8 50; return; }
  [[ ! -f ~/.ssh/config ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; return; }
  mapfile -t hosts < <(grep '^Host ' ~/.ssh/config|awk '{print $2}')
  [[ ${#hosts[@]} -eq 0 ]] && { whiptail --msgbox "Aucun host" 6 50; return; }
  CH=$(whiptail --menu "Choisissez host" 15 60 6 "${hosts[@]/#//}" 3>&1 1>&2 2>&3)||return
  awk "/^Host $CH\$/,/^Host /" ~/.ssh/config >"$SSH_DIR/sshconf_$CH"
  success "✅ Template créé → $SSH_DIR/sshconf_$CH"
}

ssh_import_host(){
  log "===== SSH IMPORT HOST ====="
  ensure_open || { whiptail --msgbox "Environnement non monté" 8 50; return; }
  [[ ! -f ~/.ssh/config ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; return; }
  mapfile -t hosts < <(grep '^Host ' ~/.ssh/config|awk '{print $2}')
  CH=$(whiptail --menu "Importer host" 15 60 6 "${hosts[@]/#//}" 3>&1 1>&2 2>&3)||return
  dst_conf="$SSH_DIR/sshconf_$CH"
  dst_keydir="$SSH_DIR/keys_$CH"
  mkdir -p "$dst_keydir"
  # extrait config
  awk "/^Host $CH\$/,/^Host /" ~/.ssh/config >"$dst_conf"
  # trouve IdentityFile et copie la clé
  idfile=$(grep -m1 'IdentityFile' "$dst_conf" |awk '{print $2}')
  if [[ -f "$idfile" ]]; then
    cp "$idfile" "$dst_keydir/" && chmod 600 "$dst_keydir/$(basename "$idfile")"
    sed -i "s|$idfile|$dst_keydir/$(basename "$idfile")|" "$dst_conf"
    log "🔸 Clé copiée → $dst_keydir/$(basename "$idfile")"
  fi
  success "✅ SSH host '$CH' importé → config: $dst_conf${idfile:+ , clé : $dst_keydir/$(basename "$idfile")}"
}

ssh_setup_alias(){
  log "===== SSH SETUP ALIAS ====="
  echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
  success "✅ Alias evsh prêt"
}

ssh_start(){
  log "===== SSH START ====="
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  [[ ${#cfgs[@]} -eq 0 ]] && { whiptail --msgbox "Pas de configs" 6 50; return; }
  tags=(); for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" "" ); done
  CH=$(whiptail --menu "Sélection config" 15 60 ${#cfgs[@]} "${tags[@]}" 3>&1 1>&2 2>&3)||return
  ssh -F "$SSH_DIR/$CH"
}

ssh_delete(){
  log "===== SSH DELETE ====="
  rm -rf "$SSH_DIR"/* && success "✅ Coffre SSH vidé"
}

ssh_backup(){
  log "===== SSH BACKUP ====="
  ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP/ssh_wallet_${ts}.tar.gz" -C "$SSH_DIR" .
  success "✅ SSH backup → $SSH_BACKUP/ssh_wallet_${ts}.tar.gz"
}

restore_ssh_wallet(){
  log "===== RESTORE SSH WALLET ====="
  mapfile -t bs < <(ls "$SSH_BACKUP"/ssh_wallet_*.tar.gz 2>/dev/null)
  [[ ${#bs[@]} -eq 0 ]] && { whiptail --msgbox "Pas de backup SSH" 6 50; return; }
  CH=$(whiptail --menu "Choisissez backup" 15 60 ${#bs[@]} "$(printf "%s\n" "${bs[@]/#//}")" 3>&1 1>&2 2>&3)||return
  tar xzf "$SSH_BACKUP/$CH" -C "$SSH_DIR"
  success "✅ SSH wallet restauré"
}

auto_open_toggle(){
  log "===== AUTO-OPEN TOGGLE ====="
  if grep -q "secure_env.sh open_env" ~/.bashrc; then
    sed -i "/secure_env.sh open_env/d" ~/.bashrc
    success "✅ Auto-open désactivé"
  else
    echo "$PWD/secure_env.sh open_env &>/dev/null" >>~/.bashrc
    success "✅ Auto-open activé"
  fi
}

# ─── Menu Whiptail ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--menu" ]]; then
  cleanup
  while true; do
    CH=$(whiptail --title "Coffre Sécurisé" --menu "Section :" 20 60 4 \
      Environnement "LUKS/ext4" \
      Cryptographie   "GPG" \
      SSH             "SSH avancé" \
      Quitter         "Quitter" \
      3>&1 1>&2 2>&3) || exit
    case $CH in
      Environnement)
        ACTION=$(whiptail --menu "Environnement" 20 60 6 \
          install_env "Installer" \
          open_env    "Ouvrir"    \
          close_env   "Fermer"    \
          delete_env  "Supprimer" \
          backup_env  "Backup"    \
          status_env  "Statut"    \
          3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      Cryptographie)
        ACTION=$(whiptail --menu "GPG" 15 60 2 \
          gpg_setup  "Setup" \
          gpg_import "Import"\
          3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      SSH)
        ACTION=$(whiptail --menu "SSH" 20 60 7 \
          ssh_create_template "ssh-create-template" \
          ssh_import_host      "ssh-import-host"      \
          ssh_setup_alias      "ssh-setup-alias"      \
          ssh_start            "ssh-start"            \
          ssh_delete           "ssh-delete"           \
          ssh_backup           "ssh-backup"           \
          restore_ssh_wallet   "restore-ssh-wallet"   \
          auto_open_toggle     "auto-open"            \
          3>&1 1>&2 2>&3)
        [[ -n "$ACTION" ]] && $ACTION ;;
      Quitter) exit ;;
    esac
    whiptail --msgbox "Opération terminée." 6 50
  done
else
  echo "Usage : $0 --menu"
fi
