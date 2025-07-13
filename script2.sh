#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail

set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & log ───────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
if [[ -n "${SUDO_USER-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="/home/$SUDO_USER"
else
  USER_HOME="$HOME"
fi
LOG="$USER_HOME/secure_env.log"; : >"$LOG"
exec 3>&1
log()    { echo "[$(date +%T)] $*" >>"$LOG"; }
info()   { echo -e "${BLUE}$*${NC}" >&3; }
success(){ echo -e "${GREEN}$*${NC}" >&3; }
error()  { echo -e "${RED}$*${NC}" >&2; }

# ─── Pré-vérifications ─────────────────────────────────────────────────────────
(( EUID==0 )) || { error "❌ Merci de relancer en root !"; exit 1; }
for cmd in cryptsetup mkfs.ext4 mount umount fallocate dd losetup lsblk df blkid pv \
           whiptail gpg ssh-keygen tar; do
  command -v "$cmd" &>/dev/null || { error "⛔ $cmd introuvable !"; exit 1; }
done

# ─── Variables globales ─────────────────────────────────────────────────────────
DEFAULT_SIZE="5G"
CONTAINER="$USER_HOME/env.img"
MAPPER="env_sec"
MOUNT="$USER_HOME/env_mount"
BACKUP="$USER_HOME/env_backups"
SSH_DIR="$MOUNT/ssh"
GPG_DIR="$MOUNT/gpg"
SSH_BACKUP_DIR="$BACKUP/ssh_wallets"
# fichier d’alias DANS le coffre
SSH_ALIAS_VAULT="$SSH_DIR/alias_env.sh"
# lien symbolique VERS le fichier d’alias
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"
INTERACTIVE=0

# préparer les répertoires
mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

spinner(){
  local pid=$1 sp='|/-\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
    sleep .1
  done
  printf "\r"
}

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

cleanup_stale(){
  mountpoint -q "$MOUNT" && { umount "$MOUNT"; log "[OK] Montage démonté"; }
  cryptsetup status "$MAPPER" &>/dev/null && { cryptsetup close "$MAPPER"; log "[OK] Mapper fermé"; }
}

ensure_env_open(){
  mountpoint -q "$MOUNT" || open_env
}

# ─── I/IV : LUKS + ext4 ────────────────────────────────────────────────────────
ask_pass(){
  read -p "Taille du conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
  SIZE=${SIZE:-$DEFAULT_SIZE}
  read -s -p "Passphrase LUKS : " PASS; echo
  read -s -p "Confirmer       : " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] || { error "❌ Passphrases différentes !"; exit 1; }
}

install_env(){
  log "== INSTALL ENV =="
  cleanup_stale; ask_pass
  if [[ -f "$CONTAINER" ]]; then
    whiptail --yesno "Le conteneur existe déjà, écraser ?" 8 50 || return
    rm -f "$CONTAINER"; log "[OK] Ancien conteneur supprimé"
  fi
  local cnt=${SIZE%[GgMm]}; [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
  info "Création du fichier ($SIZE)…"
  (
    command -v fallocate &>/dev/null && fallocate -l "$SIZE" "$CONTAINER" ||
    command -v pv       &>/dev/null && dd if=/dev/zero bs=1M count="$cnt" status=none | pv -s $((cnt*1024*1024)) >"$CONTAINER" ||
    dd if=/dev/zero bs=1M count="$cnt" of="$CONTAINER"
  ) & spinner $!
  chmod 600 "$CONTAINER"; log "[OK] Conteneur créé"
  info "Formatage LUKS (tapez YES)…"
  printf '%s' "$PASS" | cryptsetup luksFormat --batch-mode "$CONTAINER" --key-file=- & spinner $!
  log "[OK] LUKS formaté"
  info "Ouverture LUKS…"
  printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
  log "[OK] /dev/mapper/$MAPPER"
  info "Formatage ext4…"
  mkfs.ext4 "/dev/mapper/$MAPPER" & spinner $!
  log "[OK] ext4 créé"
  info "Montage…"
  mount "/dev/mapper/$MAPPER" "$MOUNT" && chmod -R go-rwx "$MOUNT"
  log "[OK] Monté sur $MOUNT"
  success "✅ Install & mount OK"; show_summary
}

open_env(){
  log "== OPEN ENV =="
  if cryptsetup status "$MAPPER" &>/dev/null; then
    info "⚠️ LUKS déjà ouvert"; log "[!!] LUKS déjà ouvert"
  else
    [[ -f "$CONTAINER" ]] || { error "❌ Conteneur manquant"; return; }
    read -s -p "Passphrase LUKS : " PASS; echo
    printf '%s' "$PASS" | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=-
    log "[OK] LUKS ouvert"
  fi
  if mountpoint -q "$MOUNT"; then
    info "⚠️ Déjà monté"; log "[!!] Déjà monté"
  else
    mount "/dev/mapper/$MAPPER" "$MOUNT" && chmod -R go-rwx "$MOUNT"
    log "[OK] Monté sur $MOUNT"
  fi
  success "✅ Environment ouvert et monté"; show_summary
}

close_env(){
  log "== CLOSE ENV =="
  mountpoint -q "$MOUNT" && { umount "$MOUNT"; log "[OK] Montage démonté"; } || { info "⚠️ Pas monté"; log "[!!] Pas monté"; }
  cryptsetup status "$MAPPER" &>/dev/null && { cryptsetup close "$MAPPER"; log "[OK] LUKS fermé"; } || { info "⚠️ Déjà fermé"; log "[!!] Déjà fermé"; }
  success "✅ Environment fermé"; show_summary
}

delete_env(){
  log "== DELETE ENV =="
  close_env
  if [[ -f "$CONTAINER" ]]; then
    rm -f "$CONTAINER"; log "[OK] Conteneur supprimé"
  else
    log "[!!] Pas de conteneur à supprimer"
  fi
  rmdir "$MOUNT" 2>/dev/null || :
  success "✅ Environment supprimé"; show_summary
}

backup_env(){
  log "== BACKUP ENV =="
  cleanup_stale
  mkdir -p "$BACKUP"
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  cp "$CONTAINER" "$BACKUP/env_${ts}.img"
  cryptsetup luksHeaderBackup "$CONTAINER" --header-backup-file "$BACKUP/env_${ts}.header"
  log "[OK] Backup container+header"
  success "✅ Backup créé dans $BACKUP"; show_summary
}

status_env(){
  log "== STATUS ENV =="
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
  df -Th | grep -E "$MAPPER|Filesystem" >>"$LOG"
  cryptsetup status "$MAPPER" &>>"$LOG" || echo "mapper fermé" >>"$LOG"
  success "✅ Statut enregistré"; show_summary
}

# ─── II : GPG ─────────────────────────────────────────────────────────────────
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
  local key; key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5; exit}')
  gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
  chmod 644 "$GPG_DIR/public_${key}.gpg"
  log "[OK] pub → $GPG_DIR/public_${key}.gpg"
  if whiptail --yesno "Exporter clé privée ?" 8 50; then
    gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"
    chmod 600 "$GPG_DIR/private_${key}.gpg"
    log "[OK] priv → $GPG_DIR/private_${key}.gpg"
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
  shopt -u nullglob
  success "✅ Import GPG terminé"; show_summary
}

# ─── III : SSH avancé ─────────────────────────────────────────────────────────
ssh_default_template(){
  log "== SSH DEFAULT TEMPLATE =="
  ensure_env_open || return
  read -p "Alias du host [monserveur]: " hname; hname=${hname:-monserveur}
  read -p "HostName (ex: example.com): " hostname; hostname=${hostname:-example.com}
  read -p "User [$(whoami)]: " user; user=${user:-$(whoami)}
  read -p "Port [22]: " port; port=${port:-22}
  tmpl="$SSH_DIR/template_${hname}.conf"
  cat >"$tmpl" <<EOF
Host $hname
  HostName $hostname
  User $user
  Port $port
  IdentityFile $SSH_DIR/${hname}_id_rsa
EOF
  chmod 644 "$tmpl"
  whiptail --msgbox "✅ Template SSH créé → $tmpl" 8 60
  log "[OK] Template par défaut $tmpl"
}

ssh_create_template(){
  log "== SSH CREATE TEMPLATE =="
  ensure_env_open || return
  [[ -f "$SSH_DIR/template_default.conf" ]] || ssh_default_template
  ssh_default_template
}

ssh_import_host(){
  log "== SSH IMPORT HOST =="
  ensure_env_open || return
  [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de ~/.ssh/config" 6 50; return; }
  mapfile -t hosts < <(grep '^Host ' "$SSH_CONFIG" | awk '{print $2}')
  (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun host trouvé" 6 50; return; }
  tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
  CH=$(whiptail --menu "Choisissez host à importer :" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return

  # extraire le bloc
  awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
  chmod 644 "$SSH_DIR/sshconf_$CH"

  # récupérer la clé privée et publique
  local idf; idf=$(awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print \$2; exit}')
  if [[ -n "$idf" ]]; then
    cp "$idf" "$SSH_DIR/"; chmod 600 "$SSH_DIR/$(basename "$idf")"
    [[ -f "${idf}.pub" ]] && { cp "${idf}.pub" "$SSH_DIR/"; chmod 644 "$SSH_DIR/$(basename "${idf}.pub")"; }
    sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
  fi

  whiptail --msgbox "✅ Host '$CH' importé dans le coffre" 6 60
  log "[OK] Host $CH importé avec clés"
}

ssh_setup_alias(){
  log "== SSH SETUP ALIAS =="
  ensure_env_open || return
  cat >"$SSH_ALIAS_VAULT" <<EOF
# Alias SSH vault
alias evsh='ssh -F $SSH_DIR/sshconf_*'
EOF
  chmod 644 "$SSH_ALIAS_VAULT"
  ln -sf "$SSH_ALIAS_VAULT" "$ALIAS_LINK"
  whiptail --msgbox "✅ Alias evsh prêt (source $ALIAS_LINK)" 6 60
  log "[OK] Alias evsh dans $SSH_ALIAS_VAULT + lien $ALIAS_LINK"
}

ssh_start(){
  log "== SSH START =="
  ensure_env_open || return
  mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
  (( ${#cfgs[@]} )) || { whiptail --msgbox "Aucune config SSH dans le coffre" 6 50; return; }
  tags=(); for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" "" ); done
  CH=$(whiptail --menu "Choisissez config SSH :" 15 60 ${#cfgs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  ssh -F "$SSH_DIR/$CH"
  success "✅ Session SSH terminée"; log "[OK] SSH session $CH"
}

ssh_delete(){
  log "== SSH DELETE =="
  ensure_env_open || return
  rm -rf "$SSH_DIR"/sshconf_* "$SSH_DIR"/*.pub "$SSH_ALIAS_VAULT"
  whiptail --msgbox "✅ Vault SSH entièrement vidé" 6 50
  log "[OK] Vault SSH vidé"
}

ssh_backup(){
  log "== SSH BACKUP =="
  ensure_env_open || return
  mkdir -p "$SSH_BACKUP_DIR"
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  tar czf "$SSH_BACKUP_DIR/ssh_wallet_${ts}.tar.gz" -C "$SSH_DIR" .
  whiptail --msgbox "✅ SSH backup créé → $SSH_BACKUP_DIR/ssh_wallet_${ts}.tar.gz" 6 60
  log "[OK] SSH backup $ts"
}

restore_ssh_wallet(){
  log "== SSH RESTORE =="
  ensure_env_open || return
  mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
  (( ${#bs[@]} )) || { whiptail --msgbox "Pas de backup SSH trouvé" 6 50; return; }
  tags=(); for b in "${bs[@]}"; do tags+=( "$(basename "$b")" "" ); done
  CH=$(whiptail --menu "Restaurer backup :" 15 60 ${#bs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
  tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
  whiptail --msgbox "✅ SSH wallet restauré → $CH" 6 60
  log "[OK] SSH wallet restauré $CH"
}

auto_open_toggle(){
  log "== AUTO-OPEN TOGGLE =="
  local me=$(basename "$0")
  if grep -q "$me open_env" "$USER_HOME/.bashrc"; then
    sed -i "/$me open_env/d" "$USER_HOME/.bashrc"
    success "✅ Auto-open désactivé"; log "[OK] Auto-open OFF"
  else
    echo "$PWD/$me open_env &>/dev/null" >>"$USER_HOME/.bashrc"
    success "✅ Auto-open activé";   log "[OK] Auto-open ON"
  fi
}

# ─── Menu principal & mode direct ────────────────────────────────────────────
cleanup_stale

if [[ "${1:-}" == "--menu" ]]; then
  INTERACTIVE=1
  while true; do
    CH=$(
      whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
        Environnement "LUKS/ext4" \
        Cryptographie "GPG" \
        SSH          "SSH avancé" \
        Quitter      "Quitter" 3>&1 1>&2 2>&3
    ) || exit 0

    case $CH in
      Environnement)
        ACTION=$(
          whiptail --title "Environnement" --menu "Opération" 20 60 6 \
            install_env     "Installer" \
            open_env        "Ouvrir"    \
            close_env       "Fermer"    \
            delete_env      "Supprimer" \
            backup_env      "Backup"    \
            status_env      "Statut"    3>&1 1>&2 2>&3
        )
        [[ -n "$ACTION" ]] && $ACTION ;;
      Cryptographie)
        ACTION=$(
          whiptail --title "GPG" --menu "Opération" 15 60 2 \
            gpg_setup  "Setup" \
            gpg_import "Import" 3>&1 1>&2 2>&3
        )
        [[ -n "$ACTION" ]] && $ACTION ;;
      SSH)
        ACTION=$(
          whiptail --title "SSH" --menu "Opération" 25 60 9 \
            ssh_default_template   "Créer template SSH" \
            ssh_import_host        "Importer host"      \
            ssh_setup_alias        "Créer alias evsh"    \
            ssh_start              "Lancer session SSH"  \
            ssh_delete             "Vider vault SSH"     \
            ssh_backup             "Backup vault SSH"    \
            restore_ssh_wallet     "Restaurer vault SSH" \
            auto_open_toggle       "Toggle auto-open"    3>&1 1>&2 2>&3
        )
        [[ -n "$ACTION" ]] && $ACTION ;;
      Quitter) exit 0 ;;
    esac
  done
else
  ACTION="${1:-}"
  if [[ -n "$ACTION" && "$(type -t "$ACTION")" == "function" ]]; then
    shift; "$ACTION" "$@"
  else
    echo "Usage: $0 --menu | <action>" >&2
    exit 1
  fi
fi
