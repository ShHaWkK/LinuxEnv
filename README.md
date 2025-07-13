Ce dépôt contient **`script2.sh`**, un script Bash autonome capable de :

1. Créer, monter et gérer un **conteneur chiffré** (fichier `env.img`)  
   → LUKS (AES-XTS) + ext4.  
2. Centraliser vos **clés GPG** dans le coffre (`gpg/`).  
3. Centraliser vos **configs & clés SSH** dans le coffre (`ssh/`).  

Le tout peut être piloté soit par un **menu TUI** (Whiptail), soit par
des **fonctions CLI**.

---

## Comment le script est structuré ?

### En-tête

* **Couleurs & journal** – tout est logué dans `~/secure_env.log`.  
* **Pré-vérifications** – les binaires indispensables sont testés ; le
  script s’arrête s’ils manquent.  
* **Variables globales** – chemins du conteneur, du montage, des
  sous-dossiers (`ssh/`, `gpg/`, etc.).

### Fonctions 'système' (LUKS / ext4)

| Fonction | Rôle interne |
|----------|--------------|
| `install_env` | Crée le fichier `env.img`, le chiffre, formate ext4, monte. |
| `open_env` / `close_env` | Ouvre/monte ou démonte/ferme le mapper LUKS. |
| `delete_env` | Supprime définitivement le conteneur. |
| `backup_env` | Copie **le conteneur ET son header** dans `env_backups/`. <br>⚠️ *~15–20 s pour 5 Gio : laissez le spinner terminer.* |
| `status_env` | Écrit état LUKS + utilisation disque dans le log. |

### Fonctions **GPG**

| Fonction | Détails |
|----------|---------|
| `gpg_setup`  | Génère une nouvelle paire (batch), sauvegarde `public_<id>.gpg` et `private_<id>.gpg`. |
| `gpg_import` | Parcourt `gpg/*.gpg` et les importe dans le trousseau local. |
| `gpg_export` | Exporte **toutes** les clés secrètes + publiques du trousseau vers le coffre. |

### 1.4 Fonctions **SSH vault**

| Fonction | Ce qu’elle fait |
|----------|-----------------|
| `ssh_create_template` | Prend un *Host* de `~/.ssh/config`, crée un template dans le vault, recopie la clé privée/publique et corrige le chemin `IdentityFile`. |
| `ssh_setup_alias` | Génère `aliases_env` → `alias evsh='ssh -F <vault>/ssh_config'` puis crée le lien `~/.aliases_env`. |
| `ssh_import_host` | Ajoute (ou remplace) un Host existant dans le vault. |
| `ssh_delete` | Vide complètement `ssh/`. |
| `ssh_backup` / `restore_ssh_wallet` | Archive / restaure le vault SSH dans `env_backups/ssh_wallet_*.tar.gz`. |
| `auto_open_toggle` | Ajoute ou retire dans `~/.bashrc` la ligne qui ouvre automatiquement le coffre à chaque nouvelle session. |

### Interface : *menu* ou *CLI*

* Si l’option `--menu` est passée **et** que `whiptail` est présent, le
  script affiche un menu (3 sections : Environnement, GPG, SSH).  
* Sinon, chaque fonction est appelée directement :  
MENU :  sudo ./script2.sh --menu
OU 
CLI : 
  ```bash
  sudo chmod +x script2.sh
  sudo ./script2.sh install_env
  sudo ./script2.sh open_env
  sudo ./script2.sh gpg_setup
...

| Tâche                                                    | Commande                                                     |
| -------------------------------------------------------- | ------------------------------------------------------------ |
| Créer le coffre (5 Gio, passphrase demandée)             | `sudo ./script2.sh install_env`                              |
| Ouvrir / Fermer                                          | `sudo ./script2.sh open_env` / `sudo ./script2.sh close_env` |
| Sauvegarder le conteneur *(≈ 15 s)*                      | `sudo ./script2.sh backup_env`                               |
| Générer une paire GPG                                    | `sudo ./script2.sh gpg_setup`                                |
| Exporter toutes les clés GPG du trousseau vers le coffre | `sudo ./script2.sh gpg_export`                               |
| Créer un template SSH à partir d’un host existant        | `sudo ./script2.sh ssh_create_template`                      |
| Installer l’alias `evsh`                                 | `sudo ./script2.sh ssh_setup_alias && source ~/.aliases_env` |
| Vider le vault SSH                                       | `sudo ./script2.sh ssh_delete`                               |


Fait par : ShHawk (Alexandre UZAN) & Julien Khalifa

