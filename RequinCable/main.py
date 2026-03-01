#!/usr/bin/python3
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Mapping des numéros de protocole
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def packet_callback(packet):
    """
    Fonction appelée automatiquement par Scapy pour chaque paquet capturé.

    Rôle :
    - Vérifier que le paquet contient une couche IPv4
    - Identifier le protocole utilisé
    - Extraire les ports si le protocole le permet (TCP/UDP)
    """

    if IP not in packet:
        return

    ip = packet[IP]
    src = ip.src
    dst = ip.dst
    proto_num = int(ip.proto)
    # Conversion du numéro de protocole en format lisible
    protocol = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")
    src_port = dst_port = None
    # TCP et UDP sont mutuellement exclusifs, on récupère la couche transport existante
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)

    # Extraction de ports source et destination si TCP ou UDP
    if transport is not None:
        src_port = int(transport.sport)
        dst_port = int(transport.dport)

    if src_port is not None and dst_port is not None:
        print(f"{src}:{src_port} -> {dst}:{dst_port} ({protocol})")
    else:
        print(f"{src} -> {dst} ({protocol})")


def main():
    # Lance la capture en temps réel sans stocker les paquets en mémoire
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    main()

# TODO: ajouter la détection du service (SSH/TCP)