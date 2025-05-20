# ciphersafe

`ciphersafe` è un progetto che utilizza una scheda ESP32 per crittografare e decrittografare file in modo sicuro. Il sistema permette di trasferire i file tra un host (PC o smartphone) e la ESP32, garantendo la riservatezza attraverso algoritmi di cifratura simmetrici.

## Caratteristiche principali

- **Crittografia e decrittografia**: supporto per AES-256 (CBC/GCM) per proteggere i file.
- **Interfaccia seriale/Wi-Fi**: possibilità di inviare e ricevere file via UART (USB) o connessione Wi-Fi.
- **Chiave sicura**: generazione e gestione delle chiavi di cifratura direttamente sulla ESP32.
- **Buffering e streaming**: gestione efficiente di file di grandi dimensioni tramite chunking.
- **Modalità CLI-friendly**: script Python per automatizzare operazioni di cifratura.

## Requisiti

### Hardware

- ESP32 (modello ESP32-WROOM-32 o equivalente)
- Cavo USB per programmazione e seriale

### Software

- [Espressif ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/)
- Python 3.7+ con librerie: