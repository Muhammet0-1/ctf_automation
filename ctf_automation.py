#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nmap # python-nmap kütüphanesi (pip install python-nmap)
import os
import sys
import time
import socket # IP adresi doğrulaması ve çözümlemesi için

# --- Yardımcı Fonksiyonlar ---

def check_nmap_installed():
    """Sistemde nmap aracının kurulu olup olmadığını kontrol eder."""
    # Basit bir kontrol: 'nmap --version' komutunu çalıştırmayı dene
    # Daha sağlam bir kontrol için shutil.which kullanılabilir (Python 3.3+)
    if os.system("nmap --version > /dev/null 2>&1") != 0:
        print("[HATA] nmap komut satırı aracı sistemde bulunamadı veya PATH içinde değil.")
        print("Lütfen nmap'i kurun (örn. 'sudo apt install nmap' veya 'sudo yum install nmap').")
        sys.exit(1)

def resolve_target(target_input):
    """Verilen hedefin (URL veya IP) geçerli bir IP adresine çözümlenmesini sağlar."""
    try:
        # Önce IP adresi mi diye kontrol et
        socket.inet_aton(target_input)
        print(f"[BİLGİ] Geçerli IP adresi: {target_input}")
        return target_input
    except socket.error:
        # IP adresi değilse, alan adı olarak çözmeyi dene
        print(f"[BİLGİ] '{target_input}' alan adı çözümleniyor...")
        try:
            ip_address = socket.gethostbyname(target_input)
            print(f"[BİLGİ] '{target_input}' -> {ip_address} olarak çözümlendi.")
            return ip_address
        except socket.gaierror:
            print(f"[HATA] Hedef '{target_input}' çözümlenemedi. Geçerli bir IP adresi veya alan adı girin.")
            return None
        except Exception as e:
            print(f"[HATA] Hedef çözümlemede beklenmedik hata: {e}")
            return None

# --- Ana Fonksiyonlar ---

def scan_target(target_ip, ports='1-1024', arguments='-sV -T4'):
    """
    Belirtilen hedef IP üzerinde Nmap taraması yapar.
    Daha kapsamlı bilgi için servis versiyon taraması (-sV) eklenmiştir.
    -T4 agresif zamanlama ile taramayı hızlandırır (ancak tespit edilebilirliği artırabilir).
    """
    print(f"\n[TARAMA] Hedef {target_ip} üzerinde port taraması başlatılıyor (Portlar: {ports}, Argümanlar: {arguments})...")
    nm = nmap.PortScanner()
    scan_results = None
    try:
        # nmap taramasını başlat
        # Not: Büyük port aralıkları veya '-p-' (tüm portlar) uzun sürebilir.
        nm.scan(hosts=target_ip, ports=ports, arguments=arguments)
        # Tarama sonuçlarını al (sadece ilk ana bilgisayar için)
        if target_ip in nm.all_hosts():
            scan_results = nm[target_ip]
            print(f"[TARAMA] Tarama tamamlandı. Durum: {scan_results.state()}")
        else:
            print(f"[HATA] Tarama sonuçlarında hedef {target_ip} bulunamadı.")

    except nmap.PortScannerError as e:
        print(f"[HATA] Nmap taraması sırasında hata oluştu: {e}")
        print("Nmap'in kurulu ve çalışır durumda olduğundan emin olun.")
    except Exception as e:
        print(f"[HATA] Tarama sırasında beklenmedik bir hata oluştu: {e}")

    return nm, scan_results # Hem nmap nesnesini hem de sonuçları döndür

def analyze_scan_results(target_ip, scan_results):
    """
    Tarama sonuçlarını analiz eder ve açık portları/servisleri listeler.
    Bu fonksiyon gerçek bir exploit yapmaz, sadece bilgi verir.
    """
    print(f"\n[ANALİZ] {target_ip} için tarama sonuçları analiz ediliyor...")
    if not scan_results:
        print("[ANALİZ] Geçerli tarama sonucu bulunamadı.")
        return [] # Boş liste döndür

    open_ports_info = [] # Açık port bilgilerini saklamak için liste

    # TCP portlarını kontrol et
    if 'tcp' in scan_results:
        print("[ANALİZ] Bulunan açık TCP portları ve servisler:")
        for port, port_info in scan_results['tcp'].items():
            if port_info['state'] == 'open':
                service = port_info.get('name', 'Bilinmiyor')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                info_str = f"  Port {port}/tcp: {service} ({product} {version})".strip()
                print(info_str)
                open_ports_info.append(info_str) # Rapor için ekle
    else:
        print("[ANALİZ] Açık TCP portu bulunamadı.")

    # UDP portlarını kontrol et (UDP taraması eklenirse çalışır, örn. arguments='-sV -sU ...')
    if 'udp' in scan_results:
        print("\n[ANALİZ] Bulunan açık UDP portları ve servisler:")
        for port, port_info in scan_results['udp'].items():
            if port_info['state'] == 'open':
                service = port_info.get('name', 'Bilinmiyor')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                info_str = f"  Port {port}/udp: {service} ({product} {version})".strip()
                print(info_str)
                open_ports_info.append(info_str) # Rapor için ekle
    # else:
        # print("[ANALİZ] Açık UDP portu bulunamadı (veya UDP taraması yapılmadı).")

    if not open_ports_info:
        print("[ANALİZ] Analiz edilecek açık port bulunamadı.")

    # --- Exploit Uyarısı ---
    print("\n[UYARI] 'Exploit' adımı sadece potansiyel hedefleri listeler.")
    print("Gerçek exploit denemeleri için manuel analiz ve özel araçlar gereklidir.")
    print("Bu araçlar sadece yasal ve izinli hedeflerde kullanılmalıdır.")
    # ---------------------

    return open_ports_info # Analiz edilen port bilgilerini döndür

def attempt_flag_detection(target_ip, open_ports_info):
    """
    Bayrak tespiti için *potansiyel* adımları gösterir (Yer Tutucu).
    Gerçek bayrak tespiti, bulunan servislere ve zafiyetlere göre
    manuel veya özel scriptler ile yapılmalıdır.
    """
    print(f"\n[BAYRAK DENEMESİ] {target_ip} üzerinde bayrak aranıyor (YER TUTUCU)...")

    if not open_ports_info:
        print("[BAYRAK DENEMESİ] Etkileşim kurulabilecek açık port bulunamadı.")
        return "Bayrak Bulunamadı (Açık Port Yok)"

    print("[BAYRAK DENEMESİ] Açık portlar üzerinden olası bayrak konumları kontrol edilebilir:")
    for info in open_ports_info:
        print(f"  -> {info}")
        # Örnek: Eğer 80 portu açıksa, web sunucusunu kontrol etmeyi düşünebilirsin.
        if "Port 80/tcp" in info or "http" in info:
            print("      * Web sunucusu (port 80) içeriği incelenebilir (örn. kaynak kodu, /flag.txt, robots.txt).")
        # Örnek: Eğer 21 portu açıksa, FTP'yi kontrol et.
        if "Port 21/tcp" in info or "ftp" in info:
            print("      * FTP sunucusu (port 21) anonim giriş veya dosyalar için kontrol edilebilir.")
        # Örnek: Eğer 22 portu açıksa, SSH'ı kontrol et.
        if "Port 22/tcp" in info or "ssh" in info:
            print("      * SSH sunucusu (port 22) zayıf şifreler veya bilinen zafiyetler için kontrol edilebilir.")
        # ... diğer portlar ve servisler için benzer kontroller eklenebilir ...

    # --- Gerçek Bayrak Tespiti Uyarısı ---
    print("\n[UYARI] Bu adım sadece olası yerleri belirtir.")
    print("Gerçek bayrak tespiti için bu servislere bağlanıp manuel inceleme")
    print("veya bulunan zafiyetlere yönelik exploit sonrası erişim gereklidir.")
    # ------------------------------------

    # Bu kısım hala bir yer tutucudur. Gerçek CTF'lerde bayrağı bulmak için
    # bu açık portlardaki servislerle etkileşime geçmek gerekir.
    detected_flag = "Bayrak Bulunamadı (Manuel Kontrol Gerekli)"
    print(f"[BAYRAK DENEMESİ] Otomatik bayrak tespiti yapılmadı. {detected_flag}")
    return detected_flag

def generate_report(target_ip, nm_scan, scan_results, open_ports_info, flag):
    """Detaylı bir tarama raporu oluşturur."""
    report_filename = f"report_{target_ip}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    print(f"\n[RAPOR] Rapor oluşturuluyor: {report_filename}")

    try:
        with open(report_filename, "w", encoding='utf-8') as report:
            report.write("="*40 + "\n")
            report.write("      CTF Makine Otomasyon Raporu\n")
            report.write("="*40 + "\n\n")
            report.write(f"Hedef IP / Alan Adı: {target_ip}\n")
            # Gerçek IP'yi ekle (eğer alan adı çözümlendiyse)
            if scan_results and target_ip != scan_results.get('addresses',{}).get('ipv4'):
                 report.write(f"Çözümlenen IP Adresi: {scan_results.get('addresses',{}).get('ipv4', 'N/A')}\n")
            report.write(f"Tarama Tarihi: {time.ctime()}\n")
            report.write(f"Nmap Komutu: {nm_scan.command_line() if nm_scan else 'N/A'}\n")

            report.write("\n--- Tarama Özeti ---\n")
            if scan_results:
                report.write(f"Durum: {scan_results.state()}\n")
                # OS Tespiti (Eğer '-O' argümanı eklenirse)
                os_match = scan_results.get('osmatch', [])
                if os_match:
                    report.write(f"İşletim Sistemi Tahmini:\n")
                    for match in os_match:
                        report.write(f"  - {match['name']} (Doğruluk: {match['accuracy']}%)\n")
                else:
                    report.write("İşletim Sistemi Tespiti yapılmadı veya başarısız.\n")

                report.write("\n--- Açık Portlar ve Servisler ---\n")
                if open_ports_info:
                    for line in open_ports_info:
                        report.write(f"{line}\n")
                else:
                    report.write("Açık port bulunamadı.\n")
            else:
                report.write("Tarama sonuçları alınamadı.\n")

            report.write("\n--- Bayrak Durumu ---\n")
            report.write(f"{flag}\n")
            report.write("\n" + "="*40 + "\n")
            report.write("         Rapor Sonu\n")
            report.write("="*40 + "\n")

        print(f"[RAPOR] Rapor başarıyla '{report_filename}' dosyasına yazıldı.")
    except Exception as e:
        print(f"[HATA] Rapor oluşturulurken hata: {e}")

# --- Ana Çalışma Bloğu ---
def main():
    """Ana betik akışını yönetir."""
    print("Basit CTF Otomasyon Betiği Başlatılıyor...")
    print("-" * 40)

    # Nmap kurulu mu kontrol et
    check_nmap_installed()

    # Kullanıcıdan hedef al
    target_input = input("Hedef IP adresini veya alan adını girin: ")
    if not target_input:
        print("[HATA] Hedef belirtilmedi. Çıkılıyor.")
        sys.exit(1)

    # Hedefi IP adresine çözümle
    target_ip = resolve_target(target_input)
    if not target_ip:
        sys.exit(1) # Çözümleme başarısızsa çık

    # 1. Port taraması yap
    # Daha kapsamlı tarama için port aralığını veya argümanları değiştirebilirsiniz
    # Örn: ports='1-65535', arguments='-sV -sC -O -T4' (daha uzun sürer)
    nm_scanner, results = scan_target(target_ip, ports='1-1024', arguments='-sV -T4')

    # 2. Tarama sonuçlarını analiz et (Exploit yerine)
    open_ports = analyze_scan_results(target_ip, results)

    # 3. Bayrak tespiti denemesi (Yer Tutucu)
    final_flag = attempt_flag_detection(target_ip, open_ports)

    # 4. Rapor oluştur
    generate_report(target_ip, nm_scanner, results, open_ports, final_flag)

    print("-" * 40)
    print("Betik tamamlandı.")

if __name__ == "__main__":
    main()

