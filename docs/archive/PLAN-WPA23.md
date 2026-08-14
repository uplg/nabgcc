# Plan WPA2/WPA3 Compatibility + Modernisation UI -- nabgcc

## 1. Diagnostic : pourquoi l'association foire

### 1.1 Ce qui fonctionne

- Le **scan** marche : `ieee80211.c` parse correctement le RSN IE (elem 48),
  extrait group/pairwise ciphers, AKM, et depuis peu `rsn_capabilities`
  (champ ajouté dans `rt2501_scan_result`).
- La **PMK** est pré-calculée côté MTL (`netPmk` = PBKDF2-SHA1-4096) et
  stockée en flash (`CONF_WIFIPMK`, offset 175, 32 octets). Correct pour
  WPA2-PSK, et identique pour WPA3-SAE transition mode (le PMK est le même
  quand l'AP accepte PSK en fallback).

### 1.2 Les bugs identifiés dans la chaîne d'association

#### Bug 1 -- RSN IE dans l'Association Request : cipher bit-shifting hack

Fichier : `vendor/nabgcc/src/net/ieee80211.c:696-741`

**RÉÉVALUATION** : après analyse approfondie, le hack bit-shifting fonctionne
correctement pour tous les cas standard :

- CCMP only (0x4A) → group=CCMP, pairwise=CCMP ✓
- TKIP group + CCMP pairwise (0x46) → group=TKIP, pairwise=CCMP ✓
- TKIP+CCMP both (0x4F) → choisit CCMP pour les deux ✓

L'encodage dans le scan (`TKIP<<1` pour group, `CCMP>>1` pour pairwise)
produit des valeurs qui, une fois décodées par le hack (masques `0x0C>>1`
et `0x03<<1`), donnent les bons octets cipher IEEE80211 (2=TKIP, 4=CCMP).

Le RSN IE contient également :
- AKM = `00:0F:AC:02` (PSK) ✓
- RSN Capability = `0x0080` (MFPC=1, MFPR=0) ✓

**Ce n'est PAS un bug.** Le code est moche mais correct.

#### Bug 2 -- Précédence opérateur MTL pour le recalcul PMK  **[CORRIGÉ]**

Fichier : `vendor/nabgcc/mtl/boot/boot.0.0.0.13.mtl` (ligne ~1915)

```
// AVANT (bug)
if crypt==IEEE80211_CRYPT_WPA || crypt==IEEE80211_CRYPT_WPA2 &&

// APRÈS (fix appliqué)
if (crypt==IEEE80211_CRYPT_WPA || crypt==IEEE80211_CRYPT_WPA2) &&
```

En Metal, `&&` est plus prioritaire que `||`. L'ancien code donnait :
`WPA || (WPA2 && changed)` au lieu de `(WPA || WPA2) && changed`.
Corrigé en ajoutant des parenthèses explicites.

#### Bug 3 -- key_desc_ver echo (déjà partiellement corrigé)

Fichier : `vendor/nabgcc/src/net/eapol.c:355-363`

Le code sauvegarde et renvoie le `key_desc_ver` de l'AP (commit récent
d'après les commentaires). C'est **correct** pour WPA2/WPA3 transition mode
où l'AP envoie `key_desc_ver=0`. Le fix est déjà en place.

Mais il manque la gestion du cas `key_desc_ver=0` pour le **calcul du MIC** :
quand `key_desc_ver=0` (AKM-defined), le MIC doit utiliser
HMAC-SHA-256 (pour SAE/WPA3) ou au minimum HMAC-SHA-1 (pour PSK). Le code
actuel utilise HMAC-SHA-1 quand le cipher est CCMP (ce qui est correct pour
WPA2-PSK mais techniquement pas pour WPA3-SAE-transitional avec
`key_desc_ver=0` qui devrait utiliser CMAC-AES-128 ou HMAC-SHA-256 selon le
type d'AKM). **En pratique**, la plupart des AP en transition mode
acceptent HMAC-SHA-1 avec PSK, donc ce n'est pas bloquant pour l'instant.

#### Bug 4 -- AES Key Unwrap pour GTK  **[DÉJÀ CORRIGÉ]**

Fichier : `vendor/nabgcc/src/net/aes128.c:297-348`

**RÉÉVALUATION** : `aes128_decrypt()` implémente déjà correctement
RFC 3394 AES Key Unwrap. L'implémentation contient :
- Boucle j=5..0, i=n..1 avec t=n*j+i (conforme RFC 3394 section 2.2.2)
- XOR big-endian de t dans A
- AES ECB decrypt de (A|R[i])
- Vérification longueur (>= 24, multiple de 8)

Le seul point faible : l'IV par défaut (0xA6...) n'est pas vérifié à la
fin (le commentaire dit "caller has no error path"). Pas bloquant — si le
PMK est correct, l'unwrap produit les bonnes données.

**Pas de correction nécessaire.**

#### Bug 5 -- gostationW ne détecte pas l'échec de connexion  **[CORRIGÉ]**

Fichier : `vendor/nabgcc/mtl/boot/boot.0.0.0.13.mtl` (ligne ~2554)

**C'est le vrai bug "stuck in connecting".**

Le handler `gostationW` ne vérifiait que `state==RT2501_S_CONNECTED`. Quand
l'association échoue (AP rejette, auth timeout, etc.), le C-side passe en
`IEEE80211_S_IDLE` → `rt2501_state()` retourne `RT2501_S_IDLE`. Mais
`gostationW` ne réagissait pas et retournait nil, laissant `wifi` en
`gostationW` indéfiniment.

Le seul filet de sécurité était le timeout de `boot_loop` (20 secondes),
mais avec 2 retries nécessaires, le fallback AP prenait ~40 secondes.

**Chaîne d'échec complète** (tracée dans le code) :

- `rt2501_state()` (`rt2501usb.c:1285`) : map direct de `ieee80211_state`
  - `IEEE80211_S_AUTH/ASSOC/EAPOL` → `RT2501_S_CONNECTING`
  - `IEEE80211_S_IDLE` → `RT2501_S_IDLE`
  - `IEEE80211_S_RUN` → `RT2501_S_CONNECTED`
- Timeouts C-side : AUTH=1s, ASSOC=1s, EAPOL=60s, RUN=60s
- `ieee80211_timer()` (`ieee80211.c:2240`) décompte et drop en IDLE à 0
- MTL `netState()` = wrapper trivial de `rt2501_state()`

Scénario typique d'échec :
1. `wifiAuth` → `netAuth` → `rt2501_auth()` envoie frame auth
2. AP rejette ou timeout (~1s) → `ieee80211_state = IDLE`
3. `rt2501_state()` retourne `RT2501_S_IDLE`
4. `gostationW` ne match que CONNECTED → retourne nil
5. `wifi` reste bloqué en `gostationW` pendant 20s (timeout boot_loop)

**Fix appliqué** : gostationW détecte IDLE et BROKEN, retry 2x immédiatement :

```
|(gostationW x-> let x -> [retries t0] in
    if state==RT2501_S_CONNECTED then (... dhcp ...)
    else if state==RT2501_S_IDLE || state==RT2501_S_BROKEN then
    (
        log "wifi fail";
        if retries<2 then (wifiAuth; gostationW [retries+1 time])
    )
)
```

Aussi réduit `BOOT_WIFITIMEOUT` de 20 à 15 secondes.

**Résultat** : au lieu d'attendre 40+ secondes avant fallback AP, le device
retry immédiatement 2 fois (~2-4s) puis le timeout de 15s finit le job.
Fallback AP en ~20s max au lieu de ~40s.

---

## 2. Plan de correction WPA2/WPA3 Compatibility Mode

### Phase 1 -- Corriger l'association (priorité critique)

#### 1a. Refactorer l'encodage cipher dans le scan

Fichier : `vendor/nabgcc/src/net/ieee80211.c` (scan beacon parsing,
~lignes 1135-1238)

Le problème est l'encodage des ciphers dans `scan_result.encryption` :
les bits bas contiennent group et pairwise encodés par décalage, ce qui
crée de la confusion dans `ieee80211_associate()`.

**Proposition** : stocker group cipher et pairwise cipher séparément.

```c
// Dans rt2501usb.h, modifier rt2501_scan_result :
struct rt2501_scan_result {
    uint8_t ssid[IEEE80211_SSID_MAXLEN+1];
    uint8_t mac[IEEE80211_ADDR_LEN];
    uint8_t bssid[IEEE80211_ADDR_LEN];
    int16_t rssi;
    uint8_t channel;
    uint16_t rateset;
    uint8_t encryption;           // WPA2, WPA, WEP, NONE (high nibble only)
    uint8_t group_cipher;         // IEEE80211_CIPHER_TKIP ou CCMP
    uint8_t pairwise_cipher;      // IEEE80211_CIPHER_TKIP ou CCMP
    uint16_t rsn_capabilities;
};
```

Puis dans `ieee80211_associate()`, utiliser directement `group_cipher` et
`pairwise_cipher` pour construire le RSN IE sans bit-shifting hack.

**Impact MTL** : `scanserialize`/`scanunserialize` dans le boot MTL
utilisent le champ `encryption` comme un seul entier. Il faudra soit :
- (a) encoder group+pairwise dans les bits bas de `encryption` de manière
  propre et documentée (ex: bits 0-3 = pairwise, bits 4-7 = group,
  bits 8-15 = type WPA/WPA2), ou
- (b) ajouter un 8e champ au tuple de scan sérialisé.

L'option (a) est préférée pour minimiser l'impact mémoire.

#### 1b. Corriger le RSN IE dans l'assoc request

Fichier : `vendor/nabgcc/src/net/ieee80211.c:696-741`

Remplacer le hack bit-shifting par un code clair :

```c
case IEEE80211_CRYPT_WPA2:
    *(write_ptr++) = 0x30;   // RSN IE
    *(write_ptr++) = 0x14;   // Length
    *(write_ptr++) = 0x01;   // Version
    *(write_ptr++) = 0x00;
    // Group cipher
    for(i=0; i<IEEE80211_OUI_LEN-1; i++)
        *(write_ptr++) = ieee80211_wpa2_oui[i];
    *(write_ptr++) = ieee80211_group_cipher;   // CCMP=4, TKIP=2
    // Pairwise count
    *(write_ptr++) = 0x01;
    *(write_ptr++) = 0x00;
    // Pairwise cipher
    for(i=0; i<IEEE80211_OUI_LEN-1; i++)
        *(write_ptr++) = ieee80211_wpa2_oui[i];
    *(write_ptr++) = ieee80211_pairwise_cipher;
    // AKM count
    *(write_ptr++) = 0x01;
    *(write_ptr++) = 0x00;
    // AKM: PSK (00:0F:AC:02)
    for(i=0; i<IEEE80211_OUI_LEN; i++)
        *(write_ptr++) = ieee80211_wpa2_oui[i];
    *(write_ptr-1) = IEEE80211_AUTH_PSK;
    // RSN Capabilities: MFPC=1, MFPR=0
    *(write_ptr++) = 0x80;
    *(write_ptr++) = 0x00;
    // Mettre à jour ieee80211_encryption avec le pairwise choisi
    ieee80211_encryption = IEEE80211_CRYPT_WPA2 | ieee80211_pairwise_cipher;
    break;
```

Ajouter des variables globales `ieee80211_group_cipher` et
`ieee80211_pairwise_cipher` remplies par `rt2501_auth()`.

#### 1c. Corriger l'initialisation cipher dans rt2501_auth

Fichier : `vendor/nabgcc/src/net/ieee80211.c:1929-1935`

Stocker les ciphers séparément quand le code WPA2 est activé :

```c
case IEEE80211_CRYPT_WPA:
case IEEE80211_CRYPT_WPA2:
    ieee80211_authmode = IEEE80211_AUTH_OPEN;
    ieee80211_group_cipher = (encryption >> 4) & 0x0F;  // ou un paramètre dédié
    ieee80211_pairwise_cipher = encryption & 0x0F;
    memcpy(ieee80211_key, key, IEEE80211_MAX_KEYLEN);
    rt2501_set_key(0, NULL, NULL, NULL, RT2501_CIPHER_NONE);
    eapol_init();
    break;
```

### Phase 2 -- Robustifier le 4-way handshake EAPOL

#### 2a. Vérifier et corriger AES Key Unwrap pour GTK

Fichier : `vendor/nabgcc/src/net/aes128.c`

Lire l'implémentation de `aes128_decrypt()`. Si c'est un simple ECB,
implémenter RFC 3394 AES Key Unwrap. Le pseudo-code est :

```
AES-Key-Unwrap(KEK, C[0..n]):
    A = C[0]
    for j = 5 downto 0:
        for i = n downto 1:
            B = AES-Decrypt(KEK, (A XOR t) || R[i])   // t = n*j + i
            A = B[0..7]
            R[i] = B[8..15]
    if A == 0xA6A6A6A6A6A6A6A6:
        return R[1..n]
    else:
        return error
```

Contrainte mémoire : l'unwrap se fait en place, ~32 octets de GTK +
8 octets d'IV = 40 octets, facilement faisable.

#### 2b. Gérer proprement key_desc_ver=0

Fichier : `vendor/nabgcc/src/net/eapol.c`

Le code gère déjà `key_desc_ver=0` en assumant CCMP (ligne 378-379).
Ajouter un commentaire explicatif et s'assurer que le MIC est bien calculé
en HMAC-SHA1 (ce qui est correct pour WPA2-PSK même avec `key_desc_ver=0`
en transition mode).

Si à terme on veut supporter SAE (vrai WPA3), il faudra KDF-SHA-256 +
CMAC-AES-128 pour le MIC. Mais c'est hors-scope pour le moment vu que le
hardware ne supporte pas SAE (pas de support de commit/confirm frames dans
le driver RT2501).

### Phase 3 -- Adapter la couche MTL

#### 3a. Corriger la précédence dans updateconf

Fichier : `vendor/nabgcc/mtl/boot/boot.0.0.0.13.mtl` (~ligne 1915)

```
// AVANT (bug)
if crypt==IEEE80211_CRYPT_WPA || crypt==IEEE80211_CRYPT_WPA2 &&

// APRES (fix)
if (crypt==IEEE80211_CRYPT_WPA || crypt==IEEE80211_CRYPT_WPA2) &&
```

#### 3b. Adapter scanserialize/scanunserialize si la struct change

Si on ajoute `group_cipher` et `pairwise_cipher` comme champs séparés dans
`rt2501_scan_result`, adapter :
- `scanserialize` : ajouter 2 champs hex de 8 chars
- `scanunserialize` : lire les 2 champs supplémentaires
- `wifiAuth` : passer les bons ciphers à `netAuth`

Alternative (recommandée pour la mémoire) : garder un seul octet
`encryption` mais avec un encodage propre :
- bits 7-4 : type (0=NONE, 1=WEP, 2=WPA, 4=WPA2)
- bits 3-2 : group cipher (1=TKIP, 2=CCMP)
- bits 1-0 : pairwise cipher (1=TKIP, 2=CCMP)

Ce qui donnerait par exemple `0x4A` = WPA2 + CCMP group + CCMP pairwise.

---

## 3. Limites hardware -- ce qu'on NE PEUT PAS faire

Le Nabaztag utilise un chipset **Ralink RT2501 (RT73)** piloté via USB.
Ce hardware a des limites strictes :

- **Pas de SAE** : le 4-way handshake SAE (Simultaneous Authentication of
  Equals) nécessite des frames Commit/Confirm (auth type 3) que le driver
  ne supporte pas. On ne fera jamais du "vrai WPA3-SAE" sur ce hardware.

- **Pas de PMF obligatoire (MFPR=1)** : les Management Frame Protection
  sont gérées par le firmware du chip RT2501 qui ne les supporte pas. On
  peut déclarer MFPC=1 (capable) dans le RSN IE pour que les AP en
  transition mode nous acceptent, mais un AP qui exige MFPR=1 (required)
  refusera l'association.

- **Pas de 802.11n/ac/ax** : le RT2501 est un chip 802.11b/g uniquement.
  Ça marche tant que l'AP supporte le legacy mode, ce qui est encore le cas
  de quasiment toutes les box en 2.4 GHz.

**En résumé** : on cible le mode **WPA2/WPA3 Transition** (aussi appelé
WPA2-PSK + WPA3-SAE Mixed Mode), où l'AP accepte à la fois WPA3-SAE et
WPA2-PSK. Le lapin se connecte en WPA2-PSK avec MFPC=1, ce qui est
exactement le scénario supporté par tous les routeurs domestiques modernes.

---

## 4. Modernisation de l'interface web

### 4.1 Contraintes

- **Mémoire** : le ML674061 a très peu de RAM. Chaque octet de HTML est
  stocké en flash sous forme de string littéral dans le bytecode MTL.
  L'interface actuelle fait ~8 Ko de HTML. On doit rester dans cet ordre
  de grandeur.
- **Pas de JS externe** : pas d'espace pour charger jQuery ou autre.
  Vanilla JS minimal uniquement.
- **Pas de CSS framework** : pas de Bootstrap. CSS inline minifié.
- **Une seule page servie à la fois** : le serveur HTTP est mono-connexion.

### 4.2 Objectifs

1. **Design moderne, léger** : mobile-first, responsive, sans framework
2. **HTML5 sémantique** : `<input type="password">`, `<select>`,
   `<fieldset>`, `<details>`, `required` attributes
3. **UX améliorée** : regroupement logique, feedback visuel, pas besoin
   de scroller 3 pages
4. **Accessibilité minimale** : labels associés, contraste correct

### 4.3 Plan de refonte

#### Etape 1 -- Nouvelle page principale (`a.htm`)

Structure proposée (une seule page, sections pliables via `<details>`) :

```
+-----------------------------------------------+
|  Nabaztag Setup               [fw: 0.0.0.13]  |
+-----------------------------------------------+
|                                                |
|  WiFi Network                                  |
|  [dropdown SSID \/]  ou  [____saisie____]      |
|                                                |
|  Security:  ( ) None  ( ) WEP  (*) WPA2        |
|  Password:  [**************************]       |
|                                                |
|  [   Connect   ]                               |
|                                                |
+-- Advanced (plié par défaut) ------------------+
|  > Network (IP/Mask/GW/DNS/DHCP)               |
|  > Proxy                                       |
|  > Server                                      |
|  > Firmware upgrade                            |
|  > Debug                                       |
+-----------------------------------------------+
```

Avantages :
- L'essentiel (WiFi + mot de passe) tient en un écran
- Les options avancées sont cachées mais accessibles
- `<details>`/`<summary>` = zéro JS, supporté partout depuis 2015
- Le formulaire upload firmware intégré dans la même page (plus besoin
  de `/u.htm` séparée)

#### Etape 2 -- CSS minimal inline

Target : < 1.5 Ko de CSS minifié. Palette :
- Background : `#f6f7fb` (déjà en place)
- Card : `#fff` avec `border-radius: 14px` (déjà en place)
- Accent : `#5b3cc4` (déjà en place)
- Input : `border: 1px solid #d9ddea`, `border-radius: 8px`, `padding: 8px 12px`
- Button : `background: #5b3cc4`, `color: #fff`, `border-radius: 8px`, full width
- `<details>` summary : `font-weight: bold`, cursor pointer

Pas de web fonts, pas de SVG, pas d'images. Purement CSS.

#### Etape 3 -- Vanilla JS minimal (~200 octets)

Un seul script pour :
- Synchroniser le dropdown SSID avec le champ texte (déjà présent, garder)
- Masquer/afficher le champ WEP auth selon le type de crypto sélectionné
- Optionnel : toggle DHCP on/off pour griser les champs IP

```html
<script>
document.querySelector('[name=m]').onchange=function(){
  document.getElementById('wep').style.display=
    this.value=='16'?'':'none'
}
</script>
```

#### Etape 4 -- Fusionner les pages

Actuellement 6 pages distinctes (`page_a`, `page_done`, `page_u`,
`page_error`, `page_debug`). Proposé :

| Actuel        | Nouveau                                              |
|---------------|------------------------------------------------------|
| `page_a`      | Page unique avec tout intégré                        |
| `page_u`      | Section `<details>` "Firmware" dans page_a           |
| `page_debug`  | Garder séparée (utile pour le debug, légère)         |
| `page_done`   | Simplifier en 3 lignes inline                        |
| `page_error`  | Simplifier en 3 lignes inline                        |

Gain mémoire estimé : ~1-2 Ko en retirant les doublons CSS et headers HTML.

#### Etape 5 -- Labels et sécurité d'affichage WPA2/WPA3

Dans le dropdown encryption, remplacer :
```
( ) WPA2
```
par :
```
( ) WPA2 / WPA3
```

C'est cosmétique mais important : l'utilisateur doit comprendre que son
lapin est compatible avec les réseaux WPA3 transition. Le code derrière
est le même (`IEEE80211_CRYPT_WPA2 = 64`).

Retirer l'option WPA (seule) du formulaire. En 2026, plus aucune box ne
fait du WPA-TKIP only. Garder None / WEP / WPA2-WPA3 comme options.

---

## 5. Ordre d'exécution (mis à jour)

| #  | Tâche                                        | Fichiers                          | Statut    |
|----|----------------------------------------------|-----------------------------------|-----------|
| 1  | ~~Fix cipher encoding dans le scan~~         | `ieee80211.c`                     | ~~PAS UN BUG~~ |
| 2  | ~~Fix RSN IE dans l'assoc request~~          | `ieee80211.c`                     | ~~PAS UN BUG~~ |
| 3  | ~~Vérifier/fix AES Key Unwrap pour GTK~~     | `aes128.c`                        | ~~DÉJÀ OK~~ |
| 4  | Fix précédence MTL dans updateconf           | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 5  | Fix gostationW fast-fail + retry             | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 6  | Réduire BOOT_WIFITIMEOUT (20→15s)            | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 7  | Refonte HTML/CSS page_a                      | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 8  | Fusion pages (u.htm dans a.htm)              | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 9  | Simplifier page_done et page_error           | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 10 | Labels WPA2/WPA3 dans l'UI                   | `boot.0.0.0.13.mtl`              | **FAIT** ✓ |
| 11 | Build firmware                               | build pipeline                    | **FAIT** ✓ |
| 12 | Test intégration complet                     | build + flash + test avec AP réel | À FAIRE   |

**Résumé des corrections WiFi** : l'association et le handshake EAPOL
fonctionnaient déjà correctement au niveau C. Le problème était dans la
couche MTL : la machine d'état `gostationW` ne détectait pas les échecs
(retour en IDLE) et attendait passivement le timeout de 20 secondes.
La correction ajoute une détection rapide + retry immédiat dans gostationW.

**Prochaine étape** : test d'intégration (étape 12) — flash + test avec AP réel.

**Build** : firmware compilé avec succès (Nab.bin = 120260 octets, Nab-wpa23.sim = 240544 octets).
Le .sim est dans `vendor/nabgcc-latest/Nab-wpa23.sim`.

---

## 6. Fichiers concernés (exhaustif)

```
vendor/nabgcc/
├── inc/
│   ├── net/
│   │   ├── ieee80211.h          # Ajouter constantes cipher si besoin
│   │   ├── eapol.h              # Pas de modif prévue
│   │   └── aes128.h             # Vérifier API Key Unwrap
│   └── usb/
│       └── rt2501usb.h          # Modifier rt2501_scan_result (optionnel)
├── src/
│   └── net/
│       ├── ieee80211.c          # Fix principal : cipher + RSN IE + auth
│       ├── eapol.c              # Fix key_desc_ver=0 + AES unwrap
│       └── aes128.c             # Vérifier implémentation decrypt
└── mtl/
    └── boot/
        └── boot.0.0.0.13.mtl   # Fix précédence + refonte HTML + scan format
```
