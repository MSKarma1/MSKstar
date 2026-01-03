# MSKstar Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python](https://img.shields.io/badge/python-3.8%2B-yellow.svg) ![Security](https://img.shields.io/badge/security-AES256-red.svg)

**[English version below]**

---

## 🇫🇷 Français

**MSKstar** est un framework de sécurité et un gestionnaire de mots de passe local ("Vault") conçu pour offrir une sécurité de niveau militaire via une interface en ligne de commande (CLI) simple et robuste.

Contrairement aux solutions cloud, MSKstar garde vos données **100% locales** sur votre machine, chiffrées dans une base de données SQLite protégée.

### Fonctionnalités Principales

*   **Chiffrement Robuste** : Utilise l'algorithme **AES-256-GCM** (Galois/Counter Mode) pour le chiffrement des données.
*   **Dérivation de Clé Sécurisée** : Protection contre les attaques par force brute via **PBKDF2-HMAC-SHA256** (600 000 itérations).
*   **Architecture "Seed-Based"** : Vos clés de chiffrement sont dérivées d'une phrase de récupération (Seed Phrase) de 12 mots, et non directement de votre mot de passe.
*   **Mode Récupération (Recovery Flow)** : Mot de passe oublié ? Utilisez votre Seed Phrase pour restaurer l'accès sans perdre vos données.
*   **Base de Données Persistante** : Gestion automatique du fichier `mskstar.db` avec détection intelligente du chemin.
*   **Bilingue** : Interface complète disponible en **Français** et **Anglais** (sélection au démarrage).

### Installation et Utilisation

#### 1. Prérequis
Vous devez avoir **Python 3.8** (ou plus récent) installé sur votre machine.

#### 2. Installation
Clonez ce dépôt et installez les dépendances nécessaires :
```bash
git clone https://github.com/MSKarma1/MSKstar.git
cd MSKstar
pip install -r requirements.txt
```

#### 3. Démarrage
Lancez simplement le script principal :
```bash
MSKSTARCLI.bat
```

### Guide de Démarrage Rapide

1.  **Initialisation** : Au premier lancement, choisissez votre langue et créez un mot de passe maître.
2.  **Seed Phrase** : Le système générera une phrase secrète de 12 mots. **Notez-la précieusement !** C'est votre seule clé de secours.
3.  **Gestion** : Utilisez le menu numérique pour Ajouter (1), Consulter (2) ou Supprimer (3) des comptes.
4.  **Récupération** : Si vous échouez 3 fois votre mot de passe lors de la connexion, le système vous proposera d'utiliser votre Seed Phrase pour réinitialiser l'accès.

---

## 🇺🇸 English

**MSKstar** is a security framework and local password manager ("Vault") designed to provide military-grade security through a simple and robust Command Line Interface (CLI).

Unlike cloud solutions, MSKstar keeps your data **100% local** on your machine, encrypted within a protected SQLite database.

### Key Features

*   **Robust Encryption**: Uses **AES-256-GCM** (Galois/Counter Mode) algorithm for data encryption.
*   **Secure Key Derivation**: Protection against brute-force attacks via **PBKDF2-HMAC-SHA256** (600,000 iterations).
*   **Seed-Based Architecture**: Your encryption keys are derived from a 12-word recovery Seed Phrase, not directly from your password.
*   **Recovery Flow**: Forgot your password? Use your Seed Phrase to restore access without losing your data.
*   **Persistent Database**: Automatic management of the `mskstar.db` file with intelligent path detection.
*   **Bilingual**: Full interface available in **French** and **English** (selectable at startup).

### Installation & Usage

#### 1. Prerequisites
You need **Python 3.8** (or newer) installed on your machine.

#### 2. Installation
Clone this repository and install the required dependencies:
```bash
git clone https://github.com/MSKarma1/MSKstar.git
cd MSKstar
pip install -r requirements.txt
```

#### 3. Start
Simply run the main script:
```bash
MSKSTARCLI.bat
```

### Quick Start Guide

1.  **Initialization**: On first launch, select your language and create a master password.
2.  **Seed Phrase**: The system will generate a 12-word secret phrase. **Write it down carefully!** This is your only backup key.
3.  **Management**: Use the numeric menu to Add (1), View (2), or Delete (3) accounts.
4.  **Recovery**: If you fail your password login 3 times, the system will offer to use your Seed Phrase to reset access.

---

### Security Details / Détails Techniques

*   **Library**: `cryptography` (Python standard for cryptographic primitives).
*   **Storage**: SQLite3 with Base64 encoding for encrypted blobs.
*   **Zero-Knowledge Architecture**: The software does not store your master password. It only stores a salted hash of the key wrapping your Seed Phrase.

### License

This project is licensed under the MIT License - see the LICENSE file for details.

**Disclaimer**: This tool is provided for educational and personal use. The author is not responsible for any data loss or forgotten passwords/seeds.
