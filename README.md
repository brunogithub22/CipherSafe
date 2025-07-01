# 🔐 CipherSafe

`CipherSafe` è un progetto open source che sfrutta una scheda **ESP32** per **crittografare e decrittografare file in modo sicuro**, garantendo la riservatezza dei dati tramite algoritmi di cifratura avanzati.

Il sistema permette lo scambio di file tra un host (PC o smartphone) e l’ESP32, sia via USB che tramite Wi-Fi, offrendo un'infrastruttura portatile, sicura e automatizzabile.

---

## ✨ Caratteristiche principali

- 🔒 **Crittografia e Decrittografia**: supporto per **AES-256** in modalità CBC e GCM.
- 🌐 **Interfaccia seriale/Wi-Fi**: trasferimento file via **UART (USB)** o rete **Wi-Fi**.
- 🔑 **Gestione chiavi sicura**: generazione e conservazione sicura delle chiavi direttamente su ESP32.
- 📦 **Streaming e buffer dinamico**: gestione efficiente di **file di grandi dimensioni** tramite chunking.
- ⚙️ **Compatibilità CLI**: script Python per integrare e automatizzare operazioni da riga di comando.

---

## 📦 Requisiti

### 🔧 Hardware

- ✅ ESP32 (preferibilmente **ESP32-WROOM-32** o equivalente)
- 🔌 Cavo USB per alimentazione, programmazione e comunicazione seriale

### 💻 Software

- 🛠️ [Espressif ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/) (v4.x o superiore consigliata)