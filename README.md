# ZeroKey - The Invisible Vault for Your Digital Life

**ZeroKey** is a next-generation, privacy-obsessed, zero-knowledge password manager for Android. Built with a "Security-by-Default" philosophy, it combines state-of-the-art cryptography with hardware-backed security to ensure your most sensitive data never leaves your control in a readable form.

---

## 🔐 Security Architecture

ZeroKey is designed so that even with full access to our servers or your physical device, your passwords remain mathematically inaccessible without your Master Password.

### 1. Hardened Key Derivation (Argon2id)
We use **Argon2id**, the winner of the Password Hashing Competition, to derive your Master Key.
- **2026 Standards**: Configured with 256MB RAM cost, 4 iterations, and 4-way parallelism to resist GPU/ASIC brute-force attacks.
- **Dynamic Salt**: Every user has a unique, cryptographically strong 16-byte salt stored in the cloud (encrypted) and locally.

### 2. Multi-Layer Envelope Encryption
Your data is protected by a 256-bit AES Vault Key, which is never stored in plaintext. It is wrapped in two distinct layers:
- **Layer 1 (User Bound)**: Wrapped using your Master Key (derived from your password).
- **Layer 2 (Hardware Bound)**: Wrapped using the **Android Keystore**, utilizing **StrongBox** or **Trusted Execution Environment (TEE)** where available. This ensures the key cannot be extracted even if the OS is compromised.

### 3. Zero-Knowledge Cloud Sync
Syncing is entirely optional and "Zero-Knowledge":
- **End-to-End Encryption**: Data is encrypted *before* it leaves your device using your private keys.
- **Metadata Protection**: Service names, usernames, and notes are all encrypted. We only see opaque blobs.
- **Rollback Protection**: Monotonic versioning and HMAC-SHA256 integrity checks prevent "Rollback Attacks" where an attacker forces your app to load an older, potentially vulnerable state.

### 4. Stealth & Anti-Tamper
- **Runtime Protection**: Detects Frida, Xposed, and other hooking frameworks.
- **Root/Debugger Detection**: Alerts users if the device environment is compromised.
- **Privacy Hardening**: Global `FLAG_SECURE` prevents screenshots/recordings; clipboards and crash logs are automatically sanitized of sensitive patterns.

---

## ✨ Key Features

- **🛡️ Secure Vault**: Full CRUD support for passwords and encrypted notes with instant search and favorites.
- **🚀 Phishing-Resistant Autofill**: A native Android Autofill service that verifies app signatures and domains before offering credentials.
- **📊 Security Dashboard**: 
    - **Entropy Analysis**: Real-time strength calculation for every password.
    - **Breach Monitoring**: Identifies passwords exposed in known data leaks.
    - **Health Score**: A holistic view of your digital security posture.
- **🤝 Secure Sharing**: Share credentials with other ZeroKey users using secure asymmetric key exchange (Tink-based).
- **⌛ Emergency Access**: A cryptographic "dead man's switch" that allows a trusted contact to recover your vault after a predefined period of inactivity.
- **🛠️ Smart Lock Policies**:
    - **Lock on App Exit**: Customizable grace periods (Immediate to 5 mins).
    - **Auth Cool Down**: Failed attempt counters reset after 30 minutes of inactivity to prevent accidental lockouts.
- **🎲 Advanced Generator**: Create high-entropy, customizable passwords on the fly.

---

## 🛠️ Technical Stack

- **UI**: 100% Jetpack Compose (Material 3)
- **Architecture**: Modular Clean Architecture with MVVM
- **Dependency Injection**: Hilt
- **Database**: Room (SQL persistence with SIV/GCM encryption)
- **Cryptography**: Google Tink, Argon2Kt, and Android Keystore
- **Backend**: Firebase Auth (Identity) & Cloud Firestore (Encrypted Blobs)
- **Concurrency**: Kotlin Coroutines & Flow

---

## 📂 Project Structure

ZeroKey is built with a highly modularized structure for better separation of concerns and build performance:
- `:app`: Main UI, ViewModels, and Feature orchestration.
- `:core:security`: The "heart" of the app - Key management, KDF, and session logic.
- `:core:crypto`: Low-level encryption primitives and Tink wrappers.
- `:core:database`: Room database definitions and DAO patterns.
- `:core:common`: Privacy-aware logging and utility functions.
- `:feature:*`: Independent modules for Vault, Settings, and Dashboard.

---

## 🚀 Getting Started

### Prerequisites
- Android Studio Ladybug (2024.2.1) or later.
- Android SDK 26+ (Android 8.0).
- A valid `google-services.json` from your Firebase project.

### Build Instructions
1. Clone the repository.
2. Place `google-services.json` in the `/app` folder.
3. Perform a **Gradle Sync**.
4. Build and Run on a physical device (recommended for Keystore features).

---

## 📜 License & Usage

**This repository is for portfolio and learning purposes only.**

© 2026 Hari. All rights reserved. 
Redistribution, modification, or commercial use of this source code is strictly prohibited without explicit written consent.

---

*ZeroKey: Because privacy shouldn't be a premium feature.*
