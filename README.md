# 🧰 CTFKit - CLI Capture The Flag Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Linux](https://img.shields.io/badge/OS-Linux-black?style=for-the-badge&logo=linux)

**CTFKit**, CTF (Capture The Flag) yarışmalarında ve güvenlik testlerinde sıkça ihtiyaç duyulan temel işlemleri (Tarama, Şifre Çözme, Dosya Analizi) tek bir komut satırı aracı altında toplayan, Python tabanlı bir "İsviçre Çakısı"dır.

Tarayıcı açıp decoder siteleriyle uğraşmak yerine, terminalinizden ayrılmadan işinizi halledin.

## 🚀 Özellikler

* **🔍 Scanner:** Nmap entegrasyonu ile hızlı port ve servis taraması.
* **🔓 Decoder:** Base64, Hex, Rot13 gibi formatları otomatik algılar ve çözer.
* **📂 Analyzer:** Dosya türünü (`file`) ve içindeki gizli metinleri (`strings`) analiz eder.
* **💻 CLI:** Argüman tabanlı (`argparse`) modern komut satırı arayüzü.

## 🛠️ Kurulum

```bash
# Projeyi klonlayın
git clone [https://github.com/Muhammet0-1/ctf_automation.git](https://github.com/Muhammet0-1/ctf_automation.git)
cd ctf_automation

# (Opsiyonel) Sistem genelinde kullanmak için alias ekleyebilirsiniz:
# alias ctfkit="python3 $(pwd)/ctfkit.py"

📖 Kullanım
1. Ağ Taraması (Scan)

Hedef makineyi tarar. Varsayılan olarak versiyon taraması (-sV) yapar.
Bash

python ctfkit.py scan 10.10.1.5
python ctfkit.py scan 10.10.1.5 -a  # Agresif tarama

2. Şifre Çözme (Decode)

Verilen metni analiz eder ve olası çözümleri (Base64, Hex, Rot13) basar.
Bash

python ctfkit.py decode "SGVsbG8gQ1RG"
# Çıktı: [+] Base64 : Hello CTF

3. Dosya Analizi (Analyze)

Bir dosyanın türünü ve içindeki okunabilir stringleri gösterir.
Bash

python ctfkit.py analyze supheli_dosya.jpg

⚠️ Yasal Uyarı

Bu araç eğitim ve CTF yarışmaları için tasarlanmıştır.