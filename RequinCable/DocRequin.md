# RequinCable
Sniffer de packets pour le projet ChausSec.

## Présentation
RequinCable est le module de capture réseau de l’infrastructure ChausSec. Il agit comme une sonde passive capable de capturer, analyser et structurer les flux réseau en temps réel.

Son rôle est de transformer les paquets réseau bruts en événements JSON structurés afin qu’ils puissent être exploités par les autres composants du SOC (API, moteur d’analyse, dashboards).


## Choix technique

### Choix du language
Nous avons décidé de développer le sniffer de paquets en Python.
Ce choix a été motivé par :
- notre maîtrise préalable du langage
- la rapidité de développement
- l’écosystème riche en outils de cybersécurité
- la simplicité de maintenance du code
Dans le contexte d’un projet académique avec des contraintes de temps, Python permet de développer rapidement un prototype fonctionnel.

### Choix de la librairie
Nous avons avions plusieurs solution possible pour le développement de RequinCable.
Nous avons choisi Scapy pour les raisons suivantes :
- bibliothèque mature et largement utilisée en cybersécurité
- intégration simple en Python
- support natif de nombreux protocoles réseau
- facilité de manipulation des paquets
Scapy permet de capturer les paquets et d’accéder directement aux différentes couches réseau.

## Installation

### Prérequis
- Python ≥ 3.11
- accès root / privilèges administrateur
- gestionnaire d'environnement Python uv
La capture réseau nécessite des privilèges élevés.

### Installation des dépendances
Les dépendances sont déclarées dans pyproject.toml.
Installation :
```bash
uv sync
```

### Lancement du sniffer
```bash
sudo uv run python main.py
```

Le programme commencera immédiatement la capture réseau.
Les événements seront affichés dans la sortie standard.


## Fonctionnalités actuelles
- Capture des paquets IPv4 en temps réel
- Extraction des champs suivants :
  - timestamp (format epoch plus simple à lire pour l'ordinateur)
  - adresse IP source
  - adresse IP destination
  - protocole (TCP, UDP, ICMP, etc.)
  - port source
  - port destination
  - service associé (résolution via la base système)
  - taille du paquet
- Conversion en événements JSON structurés
- Sortie au format JSON Lines


## Architecture du module
Le fonctionnement de RequinCable repose sur trois étapes principales.

### Capture réseau
La capture réseau est réalisée avec Scapy grâce à la fonction :
```python
sniff()
```
Chaque paquet capturé déclenche l'exécution d’une fonction de callback.

### Traitement des paquets
La fonction :
```python
packet_to_event()
```
transforme les paquets capturés en événements exploitables.

Les informations extraites incluent :
- adresses IP
- protocole réseau
- ports source et destination
- taille du paquet
- 

### Résolution du service
La fonction :
```python
detect_service()
```
permet de déterminer le service associé à un port réseau.
Elle utilise la base système :
```bash
/etc/services
```
Cela permet par exemple de transformer :
```bash
port 443 → HTTPS
port 22 → SSH
port 53 → DNS
```