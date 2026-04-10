#!/usr/bin/env python3
import os
import sys
import time
import logging
import json
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw

# -------------------------------------------------------------------------
# Configuration du système de journalisation (SIEM / Audit Trail)
# -------------------------------------------------------------------------
logging.basicConfig(
    filename='firewall_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EnterpriseFirewallManager:
    """
    Système de prévention d'intrusion (IPS) et d'audit de conformité.
    Gère l'inspection des paquets, le filtrage volumétrique et l'application des règles.
    """
    def __init__(self, policy_file="security_policy.json"):
        # Variables d'état réseau
        self.connection_rates = defaultdict(int)
        self.time_window_start = time.time()
        self.active_blocks = set()

        # Initialisation de la configuration de sécurité
        self.policy = self.load_security_policy(policy_file)
        self.max_rate_allowed = self.policy.get("max_requests_per_second", 50)
        self.trusted_zones = set(self.policy.get("trusted_ips", []))
        self.malicious_signatures = self.policy.get("signatures", [])

    def load_security_policy(self, filepath):
        """
        Charge les règles de pare-feu et les listes de confiance depuis un fichier externe.
        """
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("[i] Fichier de configuration introuvable. Chargement des paramètres par défaut.")
            return {
                "max_requests_per_second": 40,
                "trusted_ips": ["127.0.0.1", "192.168.1.254"],
                "signatures": ["GET /scripts/root.exe"]
            }

    def audit_permissive_rules(self):
        """
        Vérifie la configuration actuelle pour détecter d'éventuelles vulnérabilités
        (ex: règles Any-to-Any, seuils de tolérance anormaux).
        """
        print("[*] Lancement de l'audit de conformité des règles de pare-feu...")
        
        if "0.0.0.0" in self.trusted_zones or "0.0.0.0/0" in self.trusted_zones:
            logging.critical("AUDIT FAIL : Règle permissive détectée. Le flux 0.0.0.0/0 est autorisé.")
            print("[!] ALERTE : Règle permissive critique (Any-to-Any) détectée dans la whitelist.")
            
        if self.max_rate_allowed > 100:
            logging.warning(f"AUDIT WARN : Seuil volumétrique anormalelement élevé ({self.max_rate_allowed} req/s).")
            
        print("[+] Audit terminé. Résultats exportés dans firewall_events.log.")

    def analyze_network_flow(self, packet):
        """
        Module de Deep Packet Inspection (DPI).
        Analyse la charge utile (payload) pour identifier des signatures d'attaques.
        """
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                for signature in self.malicious_signatures:
                    if signature in payload:
                        return True
            except Exception:
                pass
        return False

    def enforce_security_policy(self, ip_address, rule_reason):
        """
        Applique dynamiquement une règle de blocage au niveau du système d'exploitation.
        """
        if ip_address not in self.active_blocks:
            os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
            self.active_blocks.add(ip_address)
            
            log_msg = f"ACTION: DROP | FLUX SRC: {ip_address} | RAISON: {rule_reason}"
            logging.info(log_msg)
            print(f"[- BLOCAGE -] {log_msg}")

    def process_packet(self, packet):
        """
        Orchestrateur principal traitant le trafic réseau en temps réel.
        """
        if not packet.haslayer(IP): 
            return

        src_ip = packet[IP].src

        # Vérification des flux approuvés
        if src_ip in self.trusted_zones:
            return

        # Inspection applicative (anti-malware / anti-exploit)
        if self.analyze_network_flow(packet):
            self.enforce_security_policy(src_ip, "Signature applicative malveillante détectée")
            return

        # Analyse comportementale (Mitigation Flood/DDoS)
        self.connection_rates[src_ip] += 1
        current_time = time.time()
        elapsed_time = current_time - self.time_window_start

        if elapsed_time >= 1.0:
            for ip, req_count in self.connection_rates.items():
                rate = req_count / elapsed_time
                if rate > self.max_rate_allowed:
                    self.enforce_security_policy(ip, f"Anomalie volumétrique détectée ({rate:.1f} paquets/s)")

            self.connection_rates.clear()
            self.time_window_start = current_time

    def start(self):
        print(f"[*] Moteur de monitoring réseau actif (Seuil de tolérance: {self.max_rate_allowed} p/s)")
        sniff(filter="ip", prn=self.process_packet, store=False)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Erreur : Ce script nécessite les privilèges Root pour modifier iptables.")
        sys.exit(1)

    firewall_manager = EnterpriseFirewallManager()
    firewall_manager.audit_permissive_rules()
    firewall_manager.start()