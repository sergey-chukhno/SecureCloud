# Guide de Configuration et Diagnostic Windows MSYS2 / MinGW pour SecureCloud
*(Windows MSYS2 / MinGW Configuration & Diagnostic Guide)*

Ce document s'adresse à Lorenzo (et à tout développeur sur Windows) pour aligner l'environnement local MSYS2 / MinGW avec la configuration de référence testée et validée dans notre pipeline CI.

---

## 1. La Distinction Cruciale des Sous-Systèmes MSYS2 (Attention Piège !)

MSYS2 propose plusieurs environnements différents via des terminaux distincts :

| Sous-système | Terminal / Exécutable | Runtime C | Préfixe des paquets `pacman` | Statut SecureCloud |
| :--- | :--- | :--- | :--- | :--- |
| **UCRT64** | `ucrt64.exe` *(bleu clair)* | `ucrtbase.dll` (moderne Microsoft) | **`mingw-w64-ucrt-x86_64-*`** | **RÉFÉRENCE CI (Recommandé)** |
| **MINGW64** | `mingw64.exe` *(bleu foncé)* | `msvcrt.dll` (legacy Windows) | `mingw-w64-x86_64-*` | Supporté mais ABI différente |
| **CLANG64** | `clang64.exe` | UCRT + LLVM/Clang | `mingw-w64-clang-x86_64-*` | Expérimental |
| **MSYS** | `msys2.exe` *(violet)* | `msys-2.0.dll` (émulation Cygwin) | `msys/*` | **INTERDIT (Ne compile pas du C++ natif Windows)** |

> [!CAUTION]
> **Ne jamais lancer `msys2.exe` (le terminal par défaut) pour compiler SecureCloud.**  
> Il faut impérativement lancer le terminal **MSYS2 UCRT64** (`C:\msys64\ucrt64.exe`) ou **MSYS2 MINGW64** (`C:\msys64\mingw64.exe`).  
> **Notre pipeline CI utilise exclusivement UCRT64.**

---

## 2. Liste des Composants et Bibliothèques Requises

Voici la liste exacte des paquets `pacman` installés dans notre pipeline GitHub Actions (`.github/workflows/ci.yml`) :

### A. Si tu es sous **UCRT64** (Configuration CI de référence) :

| Composant | Nom exact du paquet pacman | Rôle |
| :--- | :--- | :--- |
| **Compilateur & Outils** | `mingw-w64-ucrt-x86_64-toolchain` | GCC 14+, G++, Binutils, Make, Runtime |
| **Générateur de Build** | `mingw-w64-ucrt-x86_64-cmake` | CMake 3.28+ |
| **Moteur de Build** | `mingw-w64-ucrt-x86_64-ninja` | Ninja 1.11+ (Générateur ultra-rapide) |
| **Protobuf** | `mingw-w64-ucrt-x86_64-protobuf` | Protobuf C++ + compilateur `protoc.exe` |
| **gRPC** | `mingw-w64-ucrt-x86_64-grpc` | gRPC C++ Core + `grpc_cpp_plugin.exe` |
| **Cryptographie / TLS** | `mingw-w64-ucrt-x86_64-openssl` | OpenSSL 3.x (`libcrypto`, `libssl`) |
| **Tests Unitaires** | `mingw-w64-ucrt-x86_64-gtest` | GoogleTest & GoogleMock (DLLs partagées) |
| **JSON** | `mingw-w64-ucrt-x86_64-nlohmann-json` | Header-only nlohmann/json |
| **Base de Données** | `mingw-w64-ucrt-x86_64-libpqxx` | Client C++ PostgreSQL / Libpq |

**Commande d'installation directe (en une seule ligne) :**
```bash
pacman -S --needed \
  mingw-w64-ucrt-x86_64-toolchain \
  mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-ninja \
  mingw-w64-ucrt-x86_64-protobuf \
  mingw-w64-ucrt-x86_64-grpc \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-gtest \
  mingw-w64-ucrt-x86_64-nlohmann-json \
  mingw-w64-ucrt-x86_64-libpqxx
```

---

### B. Si tu es sous **MINGW64** (Legacy `msvcrt`) :

Si ton installation existante est basée sur MINGW64, voici les équivalents :
```bash
pacman -S --needed \
  mingw-w64-x86_64-toolchain \
  mingw-w64-x86_64-cmake \
  mingw-w64-x86_64-ninja \
  mingw-w64-x86_64-protobuf \
  mingw-w64-x86_64-grpc \
  mingw-w64-x86_64-openssl \
  mingw-w64-x86_64-gtest \
  mingw-w64-x86_64-nlohmann-json \
  mingw-w64-x86_64-libpqxx
```

---

## 3. Requêtes pacman pour Vérifier les Versions Exactes Installées

Pour interroger `pacman` dans ton terminal MSYS2 et connaître les versions exactes de tous les paquets installés, exécute simplement :

### Requête globale (affiche paquet + version) :
```bash
pacman -Q | grep -E "mingw-w64-(ucrt-|clang-)?(x86_64|i686)-(gcc|cmake|ninja|protobuf|grpc|openssl|gtest|nlohmann-json|libpqxx)"
```

### Requête détaillée pour un paquet spécifique :
```bash
# Exemple pour gRPC :
pacman -Qi mingw-w64-ucrt-x86_64-grpc
# ou sous MINGW64 :
pacman -Qi mingw-w64-x86_64-grpc
```

---

## 4. Script Diagnostic en 1 Clic (À Exécuter et Nous Envoyer)

Pour qu'on puisse identifier immédiatement la source du blocage (conflit de PATH, version incompatible, sous-système inadéquat), ouvre ton terminal MSYS2 habituel, colle cette commande et envoie-nous le fichier généré `lorenzo_msys2_config.txt` :

```bash
cat << 'EOF' > run_diag.sh
#!/bin/bash
echo "========================================================"
echo "          SECURECLOUD MSYS2 ENVIRONMENT REPORT          "
echo "========================================================"
echo "Date: $(date)"
echo "Host: $(uname -a)"
echo "MSYSTEM: $MSYSTEM"
echo "MSYSTEM_PREFIX: $MSYSTEM_PREFIX"
echo ""
echo "=== 1. PATH RESOLUTION ==="
echo "which gcc:       $(which gcc 2>/dev/null)"
echo "which g++:       $(which g++ 2>/dev/null)"
echo "which cmake:     $(which cmake 2>/dev/null)"
echo "which ninja:     $(which ninja 2>/dev/null)"
echo "which protoc:    $(which protoc 2>/dev/null)"
echo "which openssl:   $(which openssl 2>/dev/null)"
echo "which pkg-config:$(which pkg-config 2>/dev/null)"
echo ""
echo "=== 2. COMPILER & TOOLS VERSIONS ==="
gcc --version 2>/dev/null | head -n 1
g++ --version 2>/dev/null | head -n 1
cmake --version 2>/dev/null | head -n 1
ninja --version 2>/dev/null | head -n 1
protoc --version 2>/dev/null
openssl version 2>/dev/null
echo "Target machine: $(gcc -dumpmachine 2>/dev/null)"
echo ""
echo "=== 3. INSTALLED RELEVANT PACMAN PACKAGES ==="
pacman -Q | grep -E "(gcc|cmake|ninja|protobuf|grpc|openssl|gtest|json|pqxx)"
echo ""
echo "=== 4. WINDOWS PATH POLLUTION CHECK ==="
echo "$PATH" | tr ':' '\n' | grep -iE "(mingw|cygwin|llvm|strawberry|git|visual studio)"
echo "========================================================"
EOF
bash run_diag.sh > lorenzo_msys2_config.txt
cat lorenzo_msys2_config.txt
```

Le fichier `lorenzo_msys2_config.txt` contiendra tout ce dont on a besoin pour comprendre la divergence avec notre CI.

---

## 5. Comment Configurer et Compiler SecureCloud

Une fois les paquets installés, la compilation se fait directement avec le preset officiel :

```bash
# 1. Se placer à la racine du dépôt SecureCloud
cd /c/chemin/vers/SecureCloud

# 2. Configurer le projet avec le preset MinGW
cmake --preset ci-windows-mingw

# 3. Compiler le projet
cmake --build --preset ci-windows-mingw

# 4. Générer les certificats de test mTLS dev
bash scripts/generate-dev-pki.sh --force

# 5. Exécuter la suite de tests
ctest --preset ci-windows-mingw --output-on-failure
```

---

## 6. Questions pour Lorenzo

Pour nous permettre d'adapter le pipeline CI à ta machine si nécessaire :

1. **Quel terminal MSYS2 lances-tu ?**
   - Lances-tu bien l'icône **"MSYS2 UCRT64"** ou une autre ?
2. **Quelle est la commande exacte qui échoue chez toi ?**
   - Est-ce lors de `cmake --preset ci-windows-mingw` (étape de configuration / discovery des librairies) ?
   - Ou lors de `cmake --build --preset ci-windows-mingw` (étape de compilation C++) ?
3. **Quel est le premier message d'erreur ?**
   - Pourrais-tu copier/coller les 20 à 30 premières lignes d'erreur ?
4. **As-tu mis à jour tes paquets récemment ?**
   - Parfois, un mélange de paquets récents et anciens crée un problème d'ABI. Un `pacman -Syu` résout souvent la situation.
