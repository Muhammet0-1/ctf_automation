import nmap
import os
import time

# Kullanıcıdan hedef IP alınması
target_ip = input("Hedef IP veya URL'yi girin: ")

# Port taraması fonksiyonu
def scan_ports(target_ip):
    print(f"Target {target_ip} üzerinde port taraması yapılıyor...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-1024')  # 1-1024 portları arası tarama
    return nm

# Exploit denemesi (basit bir örnek)
def exploit_vulnerabilities(target_ip):
    print(f"Target {target_ip} üzerinde exploit denemesi yapılıyor...")
    # Burada spesifik exploitler eklenebilir.
    # Örneğin: SQL Injection, XSS, vb.
    # Basitçe açık portlara bağlanmayı deneyelim.
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-1024')
    open_ports = [port for port in nm[target_ip]['tcp'] if nm[target_ip]['tcp'][port]['state'] == 'open']
    print(f"Açık portlar: {open_ports}")
    # Exploit denemesi (örnek: sadece açık portları kullan)
    if open_ports:
        print(f"Exploit başlatılıyor açık portlar üzerinden: {open_ports}")
    else:
        print("Hiç açık port bulunamadı. Exploit yapılacak bir şey yok.")

# Flag detection fonksiyonu (basit bir örnek)
def detect_flag(target_ip):
    print("Flag tespiti başlatılıyor...")
    # Burada hedef makinadaki bayrakların bulunduğu yerler kontrol edilebilir.
    # Basitçe bir dosya okuma işlemi gibi olabilir.
    flag = "flag{dummy_flag}"
    return flag

# Rapor oluşturma fonksiyonu
def generate_report(target_ip, flag):
    with open("scan_report.txt", "w") as report:
        report.write(f"CTF Machine Automation Report\n")
        report.write(f"Target IP: {target_ip}\n")
        report.write(f"Scan Date: {time.ctime()}\n")
        report.write(f"Flag: {flag}\n")
    print("Rapor oluşturuldu: scan_report.txt")

# Ana fonksiyon
def main():
    # Port taraması yap
    nm = scan_ports(target_ip)
    
    # Exploit denemesi yap
    exploit_vulnerabilities(target_ip)
    
    # Bayrağı tespit et
    flag = detect_flag(target_ip)
    
    # Rapor oluştur
    generate_report(target_ip, flag)

if __name__ == "__main__":
    main()
