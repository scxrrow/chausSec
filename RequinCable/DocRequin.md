# RequinCable
Sniffer de packets pour le projet ChausSec.

## Présentation
RequinCable est le module de capture réseau de l’infrastructure ChausSec. Il agit comme une sonde passive capable de capturer, analyser et structurer les flux réseau en temps réel.

## Choix technique

### Choix du language
Nous avons décidé de développer le sniffer de packet dans le langage de programmation Python. Ce choix a été influencé par la maitrise du langage à l'amont du projet, ainsi que la simplicité du langage qui représente un gain de temps pour nous.

### Choix de la librairie
Nous avons avions plusieurs solution possible pour le développement de RequinCable. Nous avons décidé de partir sur Scapy.

## Fonctionnalités actuelles
- Capture des paquets IPv4 en temps réel
- Extraction des champs suivants :
  - timestamp (format ISO 8601 UTC)
  - adresse IP source
  - adresse IP destination
  - protocole (TCP, UDP, ICMP, etc.)
  - port source
  - port destination
  - service associé (résolution via la base système)
  - taille du paquet
- Conversion en événements JSON structurés
- Sortie au format JSON Lines