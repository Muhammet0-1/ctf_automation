# CTFKit

[![CI](https://github.com/Muhammet0-1/ctf_automation/actions/workflows/ci.yml/badge.svg)](https://github.com/Muhammet0-1/ctf_automation/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10--3.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CTFKit, açıkça yetkilendirilmiş yerel laboratuvarlar ve Capture The Flag ortamları için sınırlı komut satırı
yardımcıları sunar. Üç bağımsız işlevi vardır:

- Yetki ve adres kapsamı doğrulanan, hız/zaman/port sınırlarına sahip Nmap TCP connect taraması
- Base64, Base32, Base64URL, hex, URL-percent, ROT13 ve reverse için tek geçişli decode adayları
- Dosyayı çalıştırmadan SHA-256, imza, örnek entropy ve sınırlı printable string analizi

> Yalnızca sahibi olduğunuz veya açıkça test izni aldığınız hedeflerde kullanın. Bir CTF platformunda hesap
> sahibi olmak, platform dışındaki sistemleri tarama izni vermez.

## Neden yeniden tasarlandı?

İlk prototip varsayılan olarak Nmap `-sV -sC`, agresif modda `-A -T4` çalıştırıyor; hedef adresleri, port
aralıklarını ve süreyi sınırlamıyordu. Dosya analizi ise `file | strings | head` dış süreç zincirine bağlıydı.
Sürüm 1.0 saldırı yüzeyini ve yanlış kullanım riskini azaltmak için bu davranışları kaldırır.

## Güvenlik modeli

- Her tarama `--acknowledge-authorization` ister.
- Loopback, RFC1918 ve IPv6 ULA hedefleri varsayılan olarak kabul edilir.
- Global hedefler ayrıca `--allow-public-target` ister.
- Reserved, link-local, multicast, unspecified, mapped ve transition adresleri reddedilir.
- DNS en fazla sekiz adrese çözülür; mixed local/public cevaplar reddedilir ve Nmap seçilen IP'ye sabitlenir.
- Varsayılan tarama `-sT -T3`, `--max-retries 2`, `--max-rate 100` ve mutlak timeout kullanır.
- NSE scriptleri, version/OS detection, `-A`, credential attack, exploit, persistence ve evasion özelliği yoktur.
- Tam port taraması ayrı `--acknowledge-full-scan` onayı ister.
- Dosya analizi salt okunurdur; son symlink, özel dosya ve limit üstü dosyalar reddedilir.
- Decoder girdisi ve çıktısı sınırlıdır; recursive decoding veya arşiv açma yapmaz.

## Kurulum

```bash
git clone https://github.com/Muhammet0-1/ctf_automation.git
cd ctf_automation
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Decode ve analyze komutları yalnızca Python standart kütüphanesini kullanır. `scan` komutu için sistemde Nmap
bulunmalıdır.

## Yetkili tarama

HTB/TryHackMe gibi özel adres kullanan, kapsam dahilindeki bir CTF makinesi:

```bash
ctfkit scan 10.10.10.10 \
  --acknowledge-authorization
```

Belirli portlar:

```bash
ctfkit scan 10.10.10.10 \
  --acknowledge-authorization \
  --ports 22,80,443,8000-8100 \
  --format json
```

Tam port aralığı iki ayrı onay gerektirir:

```bash
ctfkit scan 10.10.10.10 \
  --acknowledge-authorization \
  --ports all \
  --acknowledge-full-scan
```

Yetkilendirilmiş global bir hedefte ayrıca `--allow-public-target` kullanılır. Bu seçenek hukuki veya
sözleşmesel izin sağlamaz; yalnızca yanlışlıkla public taramayı önleyen teknik kapıyı açar.

## Decode

```bash
ctfkit decode SGVsbG8gQ1RG
printf '%s' '48656c6c6f' | ctfkit decode --stdin --format json
```

Komut satırı argümanları süreç listesinde görünebildiğinden hassas girdiler için `--stdin` tercih edilmelidir.
Sonuçlar yalnızca olası dönüşümlerdir; otomatik olarak "şifre kırıldı" iddiasında bulunmaz.

## Salt okunur dosya analizi

```bash
ctfkit analyze challenge.bin
ctfkit analyze evidence.dat --max-strings 50 --format jsonl
```

Araç dosyayı çalıştırmaz, import etmez, extract etmez veya değiştirmez. SHA-256 dosyanın tamamından; tür,
entropy ve string gözlemleri en fazla ilk 1 MiB örnekten üretilir. Varsayılan toplam dosya sınırı 64 MiB'dir.

## Çıktı ve çıkış kodları

Her alt komut `text`, `json` ve `jsonl` çıktı sunar. Text çıktısında terminal kontrol karakterleri escape edilir;
JSON biçimleri `NaN` üretmez.

| Kod | Anlam |
| --- | --- |
| `0` | İşlem başarıyla tamamlandı |
| `1` | Çözümleme, Nmap veya dosya analizi hatası |
| `2` | CLI ya da doğrulama hatası |
| `3` | `scan --fail-on-open` seçiliyken açık port bulundu |
| `130` | Kullanıcı kesintisi |

## Sınırlamalar

CTFKit bir zafiyet tarayıcısı veya exploit framework'ü değildir. Nmap çıktısında yalnızca açık TCP portlarını ve
Nmap'in statik port tablosundaki servis adlarını raporlar. UDP taramaz, version detection veya NSE çalıştırmaz, web crawl yapmaz ve kimlik bilgisi
denemez. Magic-byte dosya tespiti sınırlı bir gözlemdir; adli analiz veya malware sandbox yerine geçmez.

## Geliştirme

```bash
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy
pytest
python -m build
```

Testler gerçek DNS, socket ve Nmap çalıştırmasını engeller; bütün dış etkiler sahte bağımlılıklarla test edilir.

Güvenlik bildirimleri için [SECURITY.md](SECURITY.md), katkı rehberi için
[CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın. Proje [MIT Lisansı](LICENSE) ile sunulur.
