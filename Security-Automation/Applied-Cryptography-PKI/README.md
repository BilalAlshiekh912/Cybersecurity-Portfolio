# Applied Cryptography & PKI: File Integrity, AES-256 Encryption, and Hardened TLS Deployment

## Executive Overview
Cryptography underpins modern security operations—from verifying file integrity during incident triage to protecting sensitive data at rest and securing network traffic in transit. 

This project implements core cryptographic controls across a hybrid Linux and Windows environment. It demonstrates cryptographic hashing for tamper detection, symmetric file encryption using AES-256-CBC, internal Public Key Infrastructure (PKI) root certificate provisioning, and the deployment of a hardened Apache HTTPS web server configured to reject legacy TLS protocols and weak cipher suites.

```text
┌──────────────────────────────────────┐         ┌──────────────────────────────────────┐
│        Ubuntu Linux Server           │         │         Windows 11 Endpoint          │
│                                      │         │                                      │
│  1. OpenSSL Mini-CA                  │         │  1. Certificate Manager (certmgr)    │
│     ├─ myCA.key (RSA 2048 Private)   │         │     └─ Trusted Root CA Store         │
│     └─ myCA.pem (X.509 Root Cert) ───┼────────►│        (Imports myCA.pem)            │
│                                      │         │                                      │
│  2. Apache2 HTTPS Server (Port 443)  │◄────────┼─ 2. Browser HTTPS Verification       │
│     ├─ TLS 1.2 / 1.3 Enforced        │  TLS    │     └─ Validates Chain of Trust      │
│     └─ Weak Ciphers Disabled         │ Handshake                                      │
└──────────────────────────────────────┘         └──────────────────────────────────────┘
```

## Technical Stack
* **Cryptographic Toolkit:** OpenSSL
* **Web Server:** Apache2 (`mod_ssl`) on Ubuntu Linux
* **Endpoint Trust Store:** Windows 11 Certificate Manager (`certmgr.msc`)
* **Algorithms & Protocols:** SHA-256, MD5, AES-256-CBC, RSA-2048, X.509, TLS 1.2/1.3

---

## Phase 1: Cryptographic Hashing & Integrity Verification

In Security Operations, cryptographic hashes serve as immutable fingerprints to verify file integrity and hunt for known Indicators of Compromise (IoCs). Even a single-byte modification triggers the **avalanche effect**, completely altering the resulting digest.

1. **Baseline Digest Generation:**
   Created a sample sensitive artifact and computed both SHA-256 and MD5 digests:
   ```bash
   echo "Confidential Report for CySA+ Lab" > report.txt
   sha256sum report.txt
   md5sum report.txt
   ```

2. **Tamper Simulation (Avalanche Effect):**
   Appended a minor modification to the file and re-evaluated the hashes:
   ```bash
   echo "Confidential Report for CySA+ Lab Part 2" > report.txt
   sha256sum report.txt
   md5sum report.txt
   ```
   *Result:* The resulting SHA-256 and MD5 hashes changed completely, confirming that unauthorized file tampering is immediately detectable via File Integrity Monitoring (FIM).

---

## Phase 2: Symmetric Encryption for Data at Rest (AES-256-CBC)

To protect sensitive data at rest from unauthorized disclosure, the artifact was encrypted using the Advanced Encryption Standard (AES) with a 256-bit key in Cipher Block Chaining (CBC) mode. Salting (`-salt`) was enforced to defend against precomputed rainbow table and dictionary attacks.

1. **Payload Encryption:**
   ```bash
   openssl enc -aes-256-cbc -salt -in report.txt -out report.enc -k StrongPass123
   ```

2. **Ciphertext Verification:**
   ```bash
   cat report.enc
   ```
   *Result:* Inspecting the raw file returned unreadable binary ciphertext, confirming that the plaintext strings were obfuscated on disk.

3. **Payload Decryption & Recovery:**
   ```bash
   openssl enc -d -aes-256-cbc -in report.enc -out report_decrypted.txt -k StrongPass123
   cat report_decrypted.txt
   ```
   *Result:* The encrypted payload was decrypted back to its original plaintext state using the symmetric key.

---

## Phase 3: Public Key Infrastructure (PKI) & Root CA Provisioning

To establish encrypted communication channels within an internal enterprise environment without relying on external commercial Certificate Authorities, a local Root CA was generated and distributed to endpoint trust stores.

1. **RSA-2048 Private Key & Self-Signed X.509 Certificate Generation:**
   Generated a 2048-bit RSA private key (`myCA.key`) and derived a self-signed X.509 root certificate (`myCA.pem`) valid for 365 days using SHA-256 signature hashing:
   ```bash
   openssl genrsa -out myCA.key 2048
   openssl req -x509 -new -nodes -key myCA.key -sha256 -days 365 -out myCA.pem
   ```

2. **Endpoint Trust Store Registration (Windows 11):**
   * Transferred `myCA.pem` from the Ubuntu server to the Windows 11 client.
   * Opened the Windows Certificate Manager (`certmgr.msc`).
   * Navigated to **Trusted Root Certification Authorities > Certificates** and imported `myCA.pem` to establish explicit endpoint trust for certificates signed by this keypair.

---

## Phase 4: Hardened HTTPS Server Deployment (Data in Transit)

With the PKI certificate provisioned, an Apache2 web server was deployed and hardened to serve content over TLS (Port 443) while stripping out vulnerable legacy protocols and weak ciphers.

1. **Apache SSL Module Provisioning:**
   ```bash
   sudo apt install -y apache2
   sudo a2enmod ssl
   sudo a2ensite default-ssl
   sudo mkdir /etc/apache2/ssl
   sudo cp myCA.key /etc/apache2/ssl/
   sudo cp myCA.pem /etc/apache2/ssl/
   ```

2. **Cryptographic Hardening (`default-ssl.conf`):**
   Configured `/etc/apache2/sites-available/default-ssl.conf` to bind the X.509 certificate and enforce strict TLS handshake parameters:
   ```apache
   <IfModule mod_ssl.c>
   <VirtualHost _default_:443>
       ServerName your.host.name
       ServerAdmin webmaster@localhost
       DocumentRoot /var/www/html

       SSLEngine on

       # Server Certificate and Private Key Bindings
       SSLCertificateFile      /etc/apache2/ssl/myCA.pem
       SSLCertificateKeyFile   /etc/apache2/ssl/myCA.key

       # Protocol Hardening: Explicitly disable SSLv3, TLS 1.0, and TLS 1.1
       SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
       SSLHonorCipherOrder     on
       
       # Cipher Suite Hardening: Reject anonymous DH, MD5, and RC4 suites
       SSLCipherSuite          HIGH:!aNULL:!MD5:!RC4

       ErrorLog ${APACHE_LOG_DIR}/error.log
       CustomLog ${APACHE_LOG_DIR}/access.log combined
   </VirtualHost>
   </IfModule>
   ```

3. **Service Restart & Validation:**
   Restarted the Apache daemon and verified the encrypted HTTPS handshake from the Windows 11 host via `https://<Ubuntu-IP>/`:
   ```bash
   sudo systemctl restart apache2
   ```

---

## Operational Security Considerations

* **Deprecation of MD5:** While `md5sum` is still occasionally referenced in legacy threat feeds, MD5 is cryptographically broken and vulnerable to collision attacks. SOC workflows should always prioritize SHA-256 (or SHA-3) for forensic integrity verification.
* **Key Derivation Hardening:** When encrypting files via the OpenSSL CLI in production environments, appending the `-pbkdf2` and `-iter 100000` flags is recommended alongside `-salt` to protect passphrases against GPU-accelerated brute-force cracking.
* **Protocol Downgrade Mitigation:** Explicitly disabling `SSLv3`, `TLSv1`, and `TLSv1.1` in the Apache configuration mitigates known cryptographic downgrade and padding oracle vulnerabilities (such as POODLE and BEAST), ensuring all data in transit utilizes modern TLS 1.2 or TLS 1.3 cipher suites.
* **Private Key Protection:** The private key (`/etc/apache2/ssl/myCA.key`) must be restricted via strict file system permissions (`chmod 600`) owned by `root:root` so unprivileged local accounts cannot exfiltrate the key and decrypt captured TLS sessions.