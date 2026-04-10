# 🛡️ Enterprise-Grade Intrusion Prevention System (IPS)

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Scapy](https://img.shields.io/badge/Library-Scapy-orange.svg)
![Security](https://img.shields.io/badge/Security-Firewall-red.svg)

## 📖 Présentation du Projet
Ce projet est une **preuve de concept (PoC)** d'un Système de Prévention d'Intrusion (IPS) développé en Python. Il a été conçu pour démontrer la compréhension des mécanismes de défense réseau, de l'inspection de paquets en profondeur (DPI) et de la gouvernance de la sécurité.

L'objectif de cet outil est de traduire des exigences métier en règles techniques appliquées dynamiquement, tout en assurant l'audit et la traçabilité des flux réseau.

## ✨ Fonctionnalités Principales
* **Audit de Conformité :** Vérification automatique des règles permissives (ex: détection de flux `Any-to-Any` / `0.0.0.0/0`) au démarrage.
* **Deep Packet Inspection (DPI) :** Analyse de la charge utile (payload) pour détecter des signatures d'attaques connues (ex: ver Nimda, SQL Injection, XSS).
* **Analyse Comportementale (Anti-DDoS) :** Surveillance volumétrique des flux et blocage dynamique des adresses IP dépassant le seuil de tolérance défini.
* **Gouvernance via JSON :** Séparation stricte entre le moteur technique et la politique de sécurité métier (`security_policy.json`).
* **Traçabilité & SIEM :** Génération de logs d'événements pour tracer toutes les ouvertures/fermetures de flux (`firewall_events.log`).
* **Remédiation Automatisée :** Interfaçage direct avec `iptables` pour l'application des blocages au niveau de l'OS (Action `DROP`).

## ⚙️ Architecture et Configuration

La politique de sécurité est centralisée dans le fichier `security_policy.json`, permettant une modification des règles sans altérer le code source :

```json
{
  "max_requests_per_second": 50,
  "trusted_ips": ["127.0.0.1", "192.168.1.254", "10.0.0.5"],
  "signatures": ["GET /scripts/root.exe", "UNION SELECT", "<script>alert"]
}

## 🚀 Installation & Prérequis

Ce script nécessite un environnement Linux, les droits administrateur (Root) pour interagir avec `iptables`, et la bibliothèque `scapy`.

```bash
# 1. Mise à jour des paquets et installation d'iptables
sudo apt update
sudo apt install iptables

# 2. Installation de Scapy
sudo apt install python3-scapy

# 3. Clonage du dépôt
git clone [https://github.com/VOTRE_PSEUDO/python-ips-firewall.git](https://github.com/VOTRE_PSEUDO/python-ips-firewall.git)
cd python-ips-firewall

## 💻 Utilisation

### 1. Démarrer le moteur IPS
Le script doit impérativement être lancé avec les privilèges `sudo`.

```bash
sudo python3 firewall.py

### 2. Simuler une attaque (Tests)
Un script de simulation (nimda.py) est fourni pour tester la réaction du pare-feu face à une signature malveillante spécifique.

Modifiez la variable cible_ip dans le script, puis lancez : sudo python3 nimda.py

## ⚠️ Avertissement
Ce projet a été développé à des fins éducatives et de démonstration technique dans le cadre d'une recherche d'alternance en Cybersécurité/Réseaux. Bien qu'il illustre des concepts réels (DPI, mitigation volumétrique), il n'est pas destiné à remplacer un équipement de sécurité matériel (type Palo Alto, Stormshield) en environnement de production.
 