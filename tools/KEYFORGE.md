# Keyforge — scripts autonomes (sans serveur)

Deux scripts Python à utiliser sous **Windows 11** (marchent aussi macOS/Linux).
Pas de navigateur, pas de serveur : on crée la clé, puis on parle à la P2S.

## 1. Créer la clé USB — `keyforge_usb.py`

Trouve ta clé USB, crée le certificat **auto-signé + sa CRL** (même émetteur =
« auto-validé », accepté par l'imprimante), et écrit tout sur la clé.

```bat
pip install cryptography
python tools\keyforge_usb.py
```
ou **double-clic sur `keyforge.bat`**. En une ligne :
```bat
python tools\keyforge_usb.py --serial 01P00A000000000 --ip 192.168.1.50 --code 12345678 --out E:\
```
Écrit dans `E:\BambooSense\` : `identity-cert.pem`, `identity-key.pem`,
`identity-crl.pem`, `connection.json`, `LISEZMOI.txt`.

## 2. Parler à la P2S — `keyforge_connect.py`

Charge la clé (détectée toute seule, ou `--bundle`), **installe le certificat**
sur l'imprimante par le réseau, puis ouvre un menu de commandes.

```bat
pip install cryptography paho-mqtt
python tools\keyforge_connect.py
```
ou **double-clic sur `connect.bat`**. Les champs demandés : **IP LAN**,
**code d'accès LAN**, **numéro de série machine** (pré-remplis depuis la clé).

Commande unique (installe le cert puis lance le **homing G28**) :
```bat
python tools\keyforge_connect.py --ip 192.168.1.50 --code 12345678 --serial 01P00A000000000 --command home
```
Autres `--command` : `status`, `light-on`, `light-off`, `pause`, `resume`,
`stop`, `clear`, `install`, `home`.

### Le menu
```
  1) Statut            4) Pause        7) Effacer erreur   0) G-code libre
  2) Lumiere ON        5) Reprise      8) Vitesse          i) Reinstaller le cert
  3) Lumiere OFF       6) Stop         9) HOMING (G28)     q) Quitter
```

## Où tourne quoi

Ces scripts parlent à l'imprimante sur **ton réseau local** (MQTT, port 8883).
Lance-les depuis un PC **sur le même réseau Wi-Fi/Ethernet que la P2S** — pas
depuis une machine distante ou le cloud, qui n'a pas de route vers l'imprimante.

## Le homing (G28) — à savoir

Le homing passe par `gcode_line`. Sur le firmware verrouillé (2025+), le G-code
doit être **chiffré vers la clé publique de l'imprimante** (`param_enc`). Cette
clé publique est renvoyée par l'imprimante au moment de `app_cert_install`, donc
le script l'installe d'abord, récupère la clé, puis chiffre « G28 » et l'envoie.
C'est pour ça que `--command home` fait toujours l'installation d'abord.

Les commandes `pause / resume / stop / print_speed / clean_print_error` sont
vérifiées sur matériel (voir `../docs/CRACK.md`). Le `gcode_line` + `param_enc`
suit la piste documentée : si l'ACK n'est pas `SUCCESS`, note l'`err_code`.

### Schéma de signature (vérifié sur matériel)

D'après la rétro-ingénierie `ClusterM/open-bamboo-networking` §10.4 (P2S/X2D,
2026) : il n'y a **aucune canonicalisation**. On signe EXACTEMENT les octets
`{"print":<valeur>}` (sans `user_id`), et le `header` est placé **EN PREMIER**
dans l'enveloppe : `{"header":{…},"print":<valeur>}`. Le firmware reconstruit
les octets signés en retirant le préfixe `{"header":…},` puis en repréfixant
`{`. La valeur `print` signée doit être **octet-pour-octet** identique à celle
émise sur le fil.

`sequence_id` doit être **≥ 2000** et non réutilisé.

### Mode sécurisé vs Mode Développeur (IMPORTANT)

Sur firmware **sécurisé** (Mode Développeur OFF), l'imprimante n'accepte une
signature `print.*` que d'un certificat qui **chaîne jusqu'à la racine Bambu**.
Un cert **auto-signé** s'installe (l'install est permissive) mais sa signature
est **rejetée** avec `err_code=84033546` (`0x0502400A`, « bad signature »).
C'est exactement ce qu'on observe sur la P2S à jour. Deux solutions :

**A) Activer le Mode Développeur** sur l'imprimante (écran → réglages). Le
firmware ignore alors la vérification de signature → les commandes `gcode_line`
**non signées** passent. L'option 9 (HOMING) essaie d'abord ce mode. C'est le
plus simple pour piloter en local.

**B) Signer avec le certificat Studio partagé de Bambu.** Même clé pour tous,
intégrée dans Bambu Studio, et le leaf correspondant est déjà de confiance sur
l'imprimante.

1. **Extraire la clé** :
   - **Recommandé (Windows)** : télécharge le binaire prêt de
     [BambuSlicerKeySaver → Releases](https://github.com/danielwoz/BambuSlicerKeySaver/releases),
     **ferme Bambu Studio**, imprimante **allumée sur le LAN**, puis double-clic
     sur `bambu_slicer_key_saver.exe`. Il écrit `slicer_key.pem`. (Les builds
     récents de Studio dérivent la clé à la volée : seul cet outil, qui pilote le
     plugin, la récupère de façon fiable.)
   - `getkey.bat` (fourni) tente d'abord une extraction par **scan mémoire**
     (Studio lancé + connecté, en Admin) — ça marche sur les anciennes versions
     de Studio, mais **pas** sur les plus récentes. Il affiche les certs vus et,
     s'il échoue, renvoie vers la solution ci-dessus.
2. **Lancer `connect.bat`** (ou `getkey.bat` l'enchaîne) : il **détecte
   automatiquement** `slicer_key.pem`
   et le cert Studio dans les emplacements habituels (dossier config + dossier
   d'installation de Studio), **dérive le `cert_id`**, **(ré)installe le leaf
   réel** avec la CRL GLOF du firmware (pour garantir la confiance), puis
   **signe** avec la clé Studio. Rien d'autre à taper.

Chemins non standard ? Précise-les :
```bat
python keyforge_connect.py --studio-key slicer_key.pem --studio-cert slicer_base64.cer
python keyforge_connect.py --studio-dir "C:\chemin\vers\BambuStudio"
```
`--no-auto-studio` désactive la détection automatique. Le script vérifie que la
clé et le cert correspondent (même modulus) et prévient sinon.

> Référence du schéma : `ClusterM/open-bamboo-networking` §10.1–10.4, §10.2
> (où vivent les secrets Studio).

### Lumière et commandes `system`

Sur le firmware verrouillé, les commandes non signées sont **ignorées sans
erreur**. La lumière (`system.ledctrl`) est donc elle aussi **signée**, et le
script affiche l'ACK réel au lieu de supposer que ça a marché.

## Sécurité

`identity-key.pem` peut commander ton imprimante : garde la clé USB comme une
clé de maison. Rien n'est utilisable sans l'IP **et** le code d'accès LAN.
