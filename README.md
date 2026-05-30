# ZeroKey - Privacy-First Password Manager

**ZeroKey** is a modern, privacy-focused, zero-knowledge password manager designed for Android. It prioritizes local security and user autonomy, ensuring that your sensitive data remains yours and yours alone.

---

## 🔒 Security Architecture

ZeroKey implements a robust "Zero-Knowledge" system, meaning no one—including the developers—can access your vault.

### 1. Hardened Key Derivation
Uses **Argon2id**, the industry-standard memory-hard function for key derivation. 
- **Parameters (2026 Standard)**: 256MB RAM cost, 4 iterations, 4 parallelism.
- **Versioning**: Supports cryptographic upgrades through versioned parameter sets.

### 2. Multi-Layer Envelope Encryption
Your Vault Key (256-bit AES) is protected by multiple layers:
- **Layer 1 (Software)**: Wrapped by a Master Key derived from your password.
- **Layer 2 (Hardware)**: Further wrapped by a Root Key stored in the **Android Keystore** (utilizing **StrongBox** or **TEE** if available).

### 3. Data Integrity
- **HMAC-SHA256**: Used for vault integrity checks to detect and prevent unauthorized data tampering.
- **Rollback Protection**: Prevents attackers from forcing the app to load an older, potentially vulnerable version of your vault.

---

## ✨ Key Features

- **🚀 Secure Vault**: Full CRUD operations for passwords, notes, and sensitive metadata.
- **🛡️ Security Dashboard**: Advanced analysis of password health (weak, duplicate, or breached passwords).
- **📱 Phishing-Resistant Autofill**: Native Android Autofill service with built-in domain verification and threat-aware behavior (auto-disables if tampering is detected).
- **☁️ Zero-Knowledge Sync**: Optional cross-device synchronization via encrypted blobs on Firestore.
- **🤝 Secure Sharing**: Share credentials with trusted contacts using ephemeral key exchange.
- **🚨 Emergency Access**: Cryptographic time-lock mechanism for vault recovery by trusted contacts in case of inactivity.
- **🕵️ Stealth Hardening**: 
    - Frida/Runtime hook detection.
    - Root and Debugger detection.
    - Global screenshot/screen-recording protection (`FLAG_SECURE`).
    - Clipboard and crash log sanitization.

---

## 🛠️ Technical Stack

- **UI**: Jetpack Compose (Declarative UI)
- **Database**: Room (SQL persistence with local encryption)
- **Networking**: Ktor
- **Backend**: Firebase Auth & Cloud Firestore
- **Encryption**: Google Tink & Argon2Kt
- **Architecture**: Modular Clean Architecture

---

## 🚀 Getting Started

### Prerequisites
- Android Studio Ladybug or later.
- JDK 17+.
- A Firebase project (for Sync/Auth features).

### Installation
1. Clone the repository.
2. Add your `google-services.json` to the `app/` directory.
3. Sync Gradle and Build.

---

## 📜 License & Usage

**This repository is public for viewing and learning purposes only.**

You may not copy, reuse, modify, redistribute, or commercialize this code without explicit permission. All rights reserved.

---

Copyright (c) 2026 Hari.
