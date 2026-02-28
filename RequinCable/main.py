#!/usr/bin/python3

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "OTHER"

        if ICMP in packet:
            protocol = "ICMP"

        elif TCP in packet:
            protocol = "TCP"

        elif UDP in packet:
            protocol = "UDP"

        print(f"{src} -> {dst} ({protocol})")


def main():
    sniff(
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":
    main()