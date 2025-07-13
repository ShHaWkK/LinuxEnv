#!/usr/bin/env bash
# secure_env.sh – Coffre sécurisé LUKS/ext4 + GPG + SSH + menu Whiptail
set -euo pipefail
export PATH="$PATH:/sbin:/usr/sbin"

# ─── Couleurs & log ───────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; BLUE='\e[34m'; NC='\e[0m'
# journal dans le home de l'utilisateur non-root
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

# ─── Pré-vérifications ────────────────────────────────────────────────────────
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
ALIAS_LINK="$USER_HOME/.aliases_env"
SSH_CONFIG="$USER_HOME/.ssh/config"
INTERACTIVE=0  # 1=menu mode, 0=direct mode

# creation dossiers
mkdir -p "${CONTAINER%/*}" "$MOUNT" "$BACKUP" "$SSH_DIR" "$GPG_DIR" "$SSH_BACKUP_DIR"

# ─── Spinner ─────────────────────────────────────────────────────────────────
spinner(){
    local pid=$1 sp='|/-\' i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${BLUE}[ %c ]${NC}" "${sp:i++%${#sp}:1}"
        sleep .1
    done
    printf "\r"
}

# ─── Résumé + derniers logs ──────────────────────────────────────────────────
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

# ─── Nettoyage stale ──────────────────────────────────────────────────────────
cleanup_stale(){
    if mountpoint -q "$MOUNT"; then
        umount "$MOUNT" && log "[OK] point de montage nettoyé"
    fi
    if cryptsetup status "$MAPPER" &>/dev/null; then
        cryptsetup close "$MAPPER" && log "[OK] mapper fermé"
    fi
}

# ─── Ouvre+monte si besoin ────────────────────────────────────────────────────
ensure_env_open(){
    if ! mountpoint -q "$MOUNT"; then
        open_env || return 1
    fi
}

# ─── PART I & IV : LUKS/ext4 ──────────────────────────────────────────────────
ask_pass(){
    read -p "Taille du conteneur (ex:5G,500M) [${DEFAULT_SIZE}] : " SIZE
    SIZE=${SIZE:-$DEFAULT_SIZE}
    read -s -p "Passphrase LUKS : " PASS; echo
    read -s -p "Confirmer       : " PASS2; echo
    [[ "$PASS" == "$PASS2" ]] || { error "❌ Passphrases différentes"; exit 1; }
}

install_env(){
    cleanup_stale; log "== INSTALL ENV =="
    ask_pass
    if [[ -f "$CONTAINER" ]]; then
        if whiptail --yesno "Le conteneur existe. Écraser ?" 8 50; then
            rm -f "$CONTAINER"; log "[OK] Ancien conteneur supprimé"
        else
            return
        fi
    fi
    local cnt=${SIZE%[GgMm]}
    [[ "$SIZE" =~ [Gg]$ ]] && cnt=$((cnt*1024))
    info "Création du fichier ($SIZE)…"
    if command -v fallocate &>/dev/null; then
        fallocate -l "$SIZE" "$CONTAINER" & spinner $!
    elif command -v pv &>/dev/null; then
        (dd if=/dev/zero bs=1M count="$cnt" status=none \
         | pv -s $((cnt*1024*1024)) >"$CONTAINER") & spinner $!
    else
        dd if=/dev/zero bs=1M count="$cnt" of="$CONTAINER" & spinner $!
        log "[!pv] pas de progression"
    fi
    chmod 600 "$CONTAINER"; log "[OK] conteneur créé"
    info "Formatage LUKS (tapez YES)…"
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
    mount "/dev/mapper/$MAPPER" "$MOUNT" && chmod -R go-rwx "$MOUNT"
    log "[OK] Monté sur $MOUNT"
    local msg="✅ Install & mount OK"
    success "$msg"; show_summary "$msg"
}

open_env(){
    cleanup_stale; log "== OPEN ENV =="
    [[ ! -f "$CONTAINER" ]] && { log "[ER] conteneur absent"; show_summary "❌ Conteneur manquant"; return; }
    if ! cryptsetup status "$MAPPER" &>/dev/null; then
        read -s -p "Passphrase LUKS : " PASS; echo
        info "Ouverture LUKS…"
        printf '%s' "$PASS" \
          | cryptsetup open "$CONTAINER" "$MAPPER" --key-file=- 
        log "[OK] LUKS ouvert"
    else
        log "[!!] LUKS déjà ouvert"
        info  "⚠️ LUKS déjà ouvert"
    fi
    if ! mountpoint -q "$MOUNT"; then
        mount "/dev/mapper/$MAPPER" "$MOUNT"
        chmod -R go-rwx "$MOUNT"
        log "[OK] Monté sur $MOUNT"
    else
        log "[!!] Déjà monté"
        info  "⚠️ Déjà monté sur $MOUNT"
    fi
    local msg="✅ Environment ouvert et monté"
    success "$msg"; show_summary "$msg"
}

close_env(){
    log "== CLOSE ENV =="
    if mountpoint -q "$MOUNT"; then
        umount "$MOUNT" && log "[OK] Monté démonté"
    else
        log "[!!] Point de montage non trouvé"
        info  "⚠️ Pas monté"
    fi
    if cryptsetup status "$MAPPER" &>/dev/null; then
        cryptsetup close "$MAPPER" && log "[OK] LUKS fermé"
    else
        log "[!!] Mapper non ouvert"
        info  "⚠️ Mapper déjà fermé"
    fi
    local msg="✅ Environment fermé"
    success "$msg"; show_summary "$msg"
}

delete_env(){
    log "== DELETE ENV =="
    close_env
    if [[ -f "$CONTAINER" ]]; then
        rm -f "$CONTAINER" && log "[OK] conteneur supprimé"
    else
        log "[!!] Pas de conteneur à supprimer"
    fi
    rmdir "$MOUNT" &>/dev/null || :
    local msg="✅ Environment supprimé"
    success "$msg"; show_summary "$msg"
}

backup_env(){
    log "== BACKUP ENV =="
    ts=$(date +%Y%m%d_%H%M%S)
    cp "$CONTAINER" "$BACKUP/env_${ts}.img"
    cryptsetup luksHeaderBackup "$CONTAINER" \
      --header-backup-file "$BACKUP/env_${ts}.header"
    log "[OK] Backup env+header"
    local msg="✅ Backup créé dans $BACKUP"
    success "$msg"; show_summary "$msg"
}

status_env(){
    log "== STATUS ENV =="
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >>"$LOG"
    df -Th | grep -E "$MAPPER|Filesystem"    >>"$LOG"
    cryptsetup status "$MAPPER"             >>"$LOG" 2>&1 || echo "mapper fermé" >>"$LOG"
    local msg="✅ Statut enregistré"
    success "$msg"; show_summary "$msg"
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
    key=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5;exit}')
    gpg --export --armor "$key" >"$GPG_DIR/public_${key}.gpg"
    log "[OK] pub → $GPG_DIR/public_${key}.gpg"
    if whiptail --yesno "Exporter la clé privée ?" 8 50; then
        gpg --export-secret-keys --armor "$key" >"$GPG_DIR/private_${key}.gpg"
        chmod 600 "$GPG_DIR/private_${key}.gpg"
        log "[OK] priv → $GPG_DIR/private_${key}.gpg"
    fi
    local msg="✅ GPG setup terminé (public+priv dans $GPG_DIR)"
    success "$msg"; show_summary "$msg"
}

gpg_import(){
    log "== GPG IMPORT =="
    ensure_env_open || return
    shopt -s nullglob
    for f in "$GPG_DIR"/*.gpg; do
        gpg --import "$f" && log "[OK] import $f"
    done
    shopt -u nullglob
    local msg="✅ Import GPG terminé (fichiers lus depuis $GPG_DIR)"
    success "$msg"; show_summary "$msg"
}

# ─── PART III : SSH avancé ─────────────────────────────────────────────────────
ssh_create_template(){
    log "== SSH CREATE TEMPLATE =="
    ensure_env_open || return
    if [[ ! -f "$SSH_CONFIG" ]]; then
        if whiptail --yesno "Pas de ~/.ssh/config. Créer un host-test ?" 8 60; then
            mkdir -p "$(dirname "$SSH_CONFIG")"
            ssh-keygen -t rsa -b 2048 -f "$USER_HOME/.ssh/id_rsa_test" -N "" -C "test-host"
            cat >>"$SSH_CONFIG" <<EOF
Host test-host
  HostName localhost
  User ${SUDO_USER:-$(whoami)}
  IdentityFile $USER_HOME/.ssh/id_rsa_test
EOF
            chmod 600 "$SSH_CONFIG"
            log "[OK] Host-test créé"
            success "✅ Host-test ajouté à $SSH_CONFIG"
        else
            whiptail --msgbox "Impossible sans config SSH" 8 50; return
        fi
    fi
    mapfile -t hosts < <(grep -E '^Host ' "$SSH_CONFIG" | awk '{print $2}')
    (( ${#hosts[@]} )) || { whiptail --msgbox "Pas de Host défini" 6 50; return; }
    tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
    CH=$(whiptail --menu "Choisissez Host →" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
    awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
    idf=$(awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2;exit}')
    if [[ -n "$idf" ]]; then
        cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")"
        sed -i "s|IdentityFile .*|IdentityFile $SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
    fi
    log "[OK] Template créé → $SSH_DIR/sshconf_$CH"
    whiptail --msgbox "✅ Template '$CH' → $SSH_DIR/sshconf_$CH" 8 60
}

ssh_setup_alias(){
    log "== SSH SETUP ALIAS =="
    ensure_env_open || return
    echo "alias evsh='ssh -F $SSH_DIR/sshconf_*'" >"$ALIAS_LINK"
    log "[OK] alias evsh dans $ALIAS_LINK"
    local msg="✅ Alias evsh prêt (source=$ALIAS_LINK)"
    success "$msg"; show_summary "$msg"
}

ssh_import_host(){
    log "== SSH IMPORT HOST =="
    ensure_env_open || return
    [[ ! -f "$SSH_CONFIG" ]] && { whiptail --msgbox "Pas de $SSH_CONFIG" 6 50; return; }
    mapfile -t hosts < <(grep -E '^Host ' "$SSH_CONFIG" | awk '{print $2}')
    (( ${#hosts[@]} )) || { whiptail --msgbox "Aucun Host" 6 50; return; }
    tags=(); for h in "${hosts[@]}"; do tags+=( "$h" "" ); done
    CH=$(whiptail --menu "Choisissez Host →" 15 60 ${#hosts[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
    awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" >"$SSH_DIR/sshconf_$CH"
    idf=$(awk "/^Host $CH\$/,/^Host /" "$SSH_CONFIG" | awk '/IdentityFile/ {print $2;exit}')
    if [[ -n "$idf" ]]; then
        cp "$idf" "$SSH_DIR/" && chmod 600 "$SSH_DIR/$(basename "$idf")"
        sed -i "s|$idf|$SSH_DIR/$(basename "$idf")|" "$SSH_DIR/sshconf_$CH"
    fi
    log "[OK] Host importé → sshconf_$CH"
    local msg="✅ SSH host importé → $SSH_DIR/sshconf_$CH"
    success "$msg"; show_summary "$msg"
}

ssh_start(){
    log "== SSH START =="
    ensure_env_open || return
    mapfile -t cfgs < <(ls "$SSH_DIR"/sshconf_* 2>/dev/null)
    (( ${#cfgs[@]} )) || { whiptail --msgbox "Aucune config SSH" 6 50; return; }
    tags=(); for f in "${cfgs[@]}"; do tags+=( "$(basename "$f")" "" ); done
    CH=$(whiptail --menu "Choisissez config →" 15 60 ${#cfgs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
    ssh -F "$SSH_DIR/$CH"
    log "[OK] Session terminée ($CH)"
    local msg="✅ SSH session $CH terminée"
    success "$msg"; show_summary "$msg"
}

ssh_delete(){
    log "== SSH DELETE =="
    ensure_env_open || return
    rm -rf "$SSH_DIR"/* && log "[OK] Coffre SSH vidé"
    local msg="✅ Vault SSH vidé"
    success "$msg"; show_summary "$msg"
}

ssh_backup(){
    log "== SSH BACKUP =="
    ensure_env_open || return
    ts=$(date +%Y%m%d_%H%M%S)
    tar czf "$SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" -C "$SSH_DIR" .
    whiptail --msgbox "Backup → $SSH_BACKUP_DIR/ssh_wallet_$ts.tar.gz" 6 60
    log "[OK] SSH backup $ts créé"
    local msg="✅ SSH backup créé"
    success "$msg"; show_summary "$msg"
}

restore_ssh_wallet(){
    log "== SSH RESTORE =="
    ensure_env_open || return
    mapfile -t bs < <(ls "$SSH_BACKUP_DIR"/ssh_wallet_*.tar.gz 2>/dev/null)
    (( ${#bs[@]} )) || { whiptail --msgbox "Pas de backup SSH" 6 50; return; }
    tags=(); for b in "${bs[@]}"; do tags+=( "$(basename "$b")" "" ); done
    CH=$(whiptail --menu "Choisissez backup →" 15 60 ${#bs[@]} "${tags[@]}" 3>&1 1>&2 2>&3) || return
    tar xzf "$SSH_BACKUP_DIR/$CH" -C "$SSH_DIR"
    whiptail --msgbox "Backup restauré → $CH" 6 60; log "[OK] restauré $CH"
    local msg="✅ SSH wallet restauré"
    success "$msg"; show_summary "$msg"
}

auto_open_toggle(){
    log "== AUTO-OPEN TOGGLE =="
    if grep -q "secure_env.sh open_env" "$USER_HOME/.bashrc"; then
        sed -i "/secure_env.sh open_env/d" "$USER_HOME/.bashrc"
        log "[OK] Auto-open OFF"; success "✅ Auto-open désactivé"
    else
        echo "$PWD/secure_env.sh open_env &>/dev/null" >>"$USER_HOME/.bashrc"
        log "[OK] Auto-open ON";  success "✅ Auto-open activé"
    fi
    show_summary
}

# ─── Menu / mode direct ───────────────────────────────────────────────────────
cleanup_stale
if [[ "${1:-}" == "--menu" ]]; then
    INTERACTIVE=1
    while true; do
        CH=$(whiptail --title "Coffre Sécurisé" --menu "Section" 15 60 4 \
            Environnement "LUKS/ext4" \
            Cryptographie   "GPG" \
            SSH             "SSH avancé" \
            Quitter         "Quitter" \
            3>&1 1>&2 2>&3) || exit
        case $CH in
            Environnement)
                ACTION=$(whiptail --title "Environnement" \
                  --menu "Choisissez" 20 60 6 \
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
                ACTION=$(whiptail --title "GPG" \
                  --menu "Choisissez" 15 60 2 \
                  gpg_setup  "Setup" \
                  gpg_import "Import" \
                  3>&1 1>&2 2>&3)
                [[ -n "$ACTION" ]] && $ACTION
                ;;
            SSH)
                ACTION=$(whiptail --title "SSH" \
                  --menu "Choisissez" 25 60 7 \
                  ssh_create_template "ssh-template" \
                  ssh_setup_alias     "alias evsh"     \
                  ssh_import_host     "import-host"    \
                  ssh_start           "start"          \
                  ssh_delete          "delete"         \
                  ssh_backup          "backup"         \
                  restore_ssh_wallet  "restore"        \
                  auto_open_toggle    "auto-open"      \
                  3>&1 1>&2 2>&3)
                [[ -n "$ACTION" ]] && $ACTION
                ;;
            Quitter) exit 0 ;;
        esac
    done
else
    ACTION="${1:-}"
    if [[ -n "$ACTION" && $(type -t "$ACTION") == "function" ]]; then
        shift; "$ACTION" "$@"
    else
        echo "Usage: $0 --menu | <action>" >&2
        exit 1
    fi
fi
