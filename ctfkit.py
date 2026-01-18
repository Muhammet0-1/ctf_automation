#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import subprocess
import base64
import binascii
import codecs
import shutil
from datetime import datetime


# === RENKLENDİRME (Arch Linux Terminali İçin) ===
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# === YARDIMCI SINIFLAR ===

class CTFKit:
    def __init__(self):
        self.banner()
        self.parser = argparse.ArgumentParser(description="CTFKit - All-in-One CTF Toolkit")
        self.subparsers = self.parser.add_subparsers(dest="command", help="Komutlar")

        # 1. SCAN (Tarama) Modülü
        scan_parser = self.subparsers.add_parser("scan", help="Hedef sistemde Nmap taraması yapar")
        scan_parser.add_argument("target", help="Hedef IP veya Alan Adı")
        scan_parser.add_argument("-p", "--ports", default="default", help="Port aralığı (örn: 1-1000 veya 'all')")
        scan_parser.add_argument("-a", "--aggressive", action="store_true", help="Agresif tarama (-A)")

        # 2. DECODE (Şifre Çözme) Modülü
        decode_parser = self.subparsers.add_parser("decode", help="Base64, Hex, Rot13 çözücü")
        decode_parser.add_argument("string", help="Çözülecek şifreli metin")

        # 3. ANALYZE (Dosya Analizi) Modülü
        analyze_parser = self.subparsers.add_parser("analyze", help="Dosya türü ve Strings analizi")
        analyze_parser.add_argument("file", help="Analiz edilecek dosya yolu")

    def banner(self):
        print(f"{Colors.GREEN}{Colors.BOLD}")
        print(r"""
   ______ ______ ______   _  __  _  __
  / ____//_  __// ____/  | |/ / (_)/ /_
 / /      / /  / /_      |   / / // __/
/ /___   / /  / __/     /   | / // /_  
\____/  /_/  /_/       /_/|_|/_/ \__/  
        v1.0 - CTF Swiss Army Knife
        """)
        print(f"{Colors.ENDC}")

    def run(self):
        if len(sys.argv) < 2:
            self.parser.print_help()
            sys.exit(1)

        args = self.parser.parse_args()

        if args.command == "scan":
            self.handle_scan(args)
        elif args.command == "decode":
            self.handle_decode(args)
        elif args.command == "analyze":
            self.handle_analyze(args)

    # --- MODÜL: SCANNER ---
    def handle_scan(self, args):
        print(f"{Colors.YELLOW}[*] Hedef: {args.target} taranıyor...{Colors.ENDC}")

        if not shutil.which("nmap"):
            print(f"{Colors.RED}[!] HATA: Nmap yüklü değil!{Colors.ENDC}")
            return

        cmd = ["nmap", args.target]

        if args.ports == "all":
            cmd.extend(["-p-"])
        elif args.ports != "default":
            cmd.extend(["-p", args.ports])

        if args.aggressive:
            cmd.extend(["-A", "-T4"])
        else:
            cmd.extend(["-sV", "-sC"])

        print(f"{Colors.BLUE}[cmd] {' '.join(cmd)}{Colors.ENDC}")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Tarama iptal edildi.{Colors.ENDC}")

    # --- MODÜL: DECODER ---
    def handle_decode(self, args):
        data = args.string
        print(f"{Colors.YELLOW}[*] '{data}' için olası çözümler aranıyor...{Colors.ENDC}\n")

        # 1. Base64
        try:
            # Padding düzeltme
            padded_data = data + '=' * (-len(data) % 4)
            b64 = base64.b64decode(padded_data).decode('utf-8', errors='ignore')
            if b64 and b64.isprintable():
                print(f"{Colors.GREEN}[+] Base64 :{Colors.ENDC} {b64}")
        except:
            pass

        # 2. Hex
        try:
            h = bytes.fromhex(data).decode('utf-8', errors='ignore')
            if h and h.isprintable():
                print(f"{Colors.GREEN}[+] Hex    :{Colors.ENDC} {h}")
        except:
            pass

        # 3. Rot13
        try:
            r13 = codecs.decode(data, 'rot_13')
            print(f"{Colors.GREEN}[+] Rot13  :{Colors.ENDC} {r13}")
        except:
            pass

        # 4. Reverse
        print(f"{Colors.GREEN}[+] Reverse:{Colors.ENDC} {data[::-1]}")

    # --- MODÜL: ANALYZER ---
    def handle_analyze(self, args):
        filepath = args.file
        if not os.path.exists(filepath):
            print(f"{Colors.RED}[!] Dosya bulunamadı: {filepath}{Colors.ENDC}")
            return

        print(f"{Colors.YELLOW}[*] Dosya Analizi: {filepath}{Colors.ENDC}")

        # File Command
        try:
            output = subprocess.check_output(["file", filepath]).decode().strip()
            print(f"{Colors.BLUE}[TYPE]{Colors.ENDC} {output}")
        except:
            pass

        # Strings (İlk 10 satır)
        print(f"\n{Colors.YELLOW}[*] İçindeki okunabilir veriler (strings - ilk 10):{Colors.ENDC}")
        try:
            # strings komutu linux'ta genelde vardır
            p1 = subprocess.Popen(["strings", filepath], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["head", "-n", "10"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()
            output = p2.communicate()[0].decode()
            print(output)
            print(f"{Colors.BLUE}...daha fazlası için 'strings {filepath}' kullanın.{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.RED}[!] 'strings' komutu bulunamadı.{Colors.ENDC}")


if __name__ == "__main__":
    kit = CTFKit()
    kit.run()