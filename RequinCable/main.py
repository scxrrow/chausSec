#!/usr/bin/python3
"""
RequinCable - Sniffeur de Packet pour chausSec

Capture les packets réseaux en utilisant Scapy, et les converti en event JSON.

Autheur : Dan JEONG
Contributeurs : 
Projet: ChausSec
"""

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import socket
import json
import time

# Mapping des numéros de protocole
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def detect_service(protocol: str, src_port: int | None, dst_port: int | None) -> str | None:
    """
    Résout le nom du service associé à un port. 
    Le port destination est testé en priorité car il correspond généralement au service cible.
    """
    if protocol not in ("TCP", "UDP"):
        return None

    proto = protocol.lower()

    for port in (dst_port, src_port):
        if port is None:
            continue
        try:
            return socket.getservbyport(port, proto).upper()
        except OSError:
            pass

    return None


def iso_utc_from_epoch(t: float) -> str:
    """
    Convertit un timestamp epoch en format ISO 8601 UTC avec millisecondes.
    """
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1)*1000):03d}Z"
    

def packet_to_event(packet) -> dict | None:
    """
    Transforme un paquet Scapy en événement JSON-ready.
    Retourne None si paquet non IPv4.
    """
    if IP not in packet:
        return None

    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto_num = int(ip.proto)
    protocol = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")

    src_port = dst_port = None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    if transport is not None:
        src_port = int(transport.sport)
        dst_port = int(transport.dport)

    service = detect_service(protocol, src_port, dst_port)

    event = {
        "ts": iso_utc_from_epoch(float(packet.time)),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "service": service,
        "len": len(packet),
    }
    return event


def packet_callback(packet) -> None:
    """
    Fonction appelée automatiquement par Scapy pour chaque paquet capturé.
    Convertit le paquet en événement JSON et l écrit sur la sortie standard.
    """
    event = packet_to_event(packet)
    if event is None:
        return

    print(json.dumps(event, separators=(",", ":"), ensure_ascii=False), flush=True)


def main():
    """
    Point d’entrée principal. Démarre la capture réseau en temps réel.
    """
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    main()

# TODO: Division des fonctions en sous fichiers
# TODO: Filtre BFP