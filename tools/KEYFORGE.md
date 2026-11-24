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

`err_code=84033546` (`0x0502400A`) = **« bad signature »** (et non « cert
absent », qui serait `84033545`). Notre erreur venait du `header` placé à la
**fin** : l'imprimante incluait alors le header dans sa reconstruction →
signature fausse. Corrigé en mettant le header en tête.

`sequence_id` doit être **≥ 2000** et non réutilisé.

### Lumière et commandes `system`

Sur le firmware verrouillé, les commandes non signées sont **ignorées sans
erreur**. La lumière (`system.ledctrl`) est donc elle aussi **signée**, et le
script affiche l'ACK réel au lieu de supposer que ça a marché.

## Sécurité

`identity-key.pem` peut commander ton imprimante : garde la clé USB comme une
clé de maison. Rien n'est utilisable sans l'IP **et** le code d'accès LAN.
