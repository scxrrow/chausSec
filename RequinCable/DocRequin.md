# RequinCable
Sniffer de packets pour le projet ChausSec.

## Présentation
RequinCable est le module de capture réseau de l’infrastructure ChausSec. Il agit comme une sonde passive capable de capturer, analyser et structurer les flux réseau en temps réel.

## Choix technique

### Choix du language
Nous avons décidé de développer le sniffer de packet dans le langage de programmation Python. Ce choix a été influencé par la maitrise du langage à l'amont du projet, ainsi que la simplicité du langage qui représente un gain de temps pour nous.

### Choix de la librairie
Nous avons avions plusieurs solution possible pour le développement de RequinCable. Nous avons décidé de partir sur Scapy.

## Architecture
le fichier main.py est le point d'entrée de RequinCable. C'est le fichier à éxecuter.

## Execution
Il est pour le moment nécessaire d'exécuter le fichier main.py avec sudo.
