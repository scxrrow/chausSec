#!/usr/bin/python3

from scapy.all import sniff
from scapy.layers.inet import IP


def packet_callback(packet):

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        print(f"{src} -> {dst}")


def main():

    sniff(
        prn=packet_callback,
        store=False,
        count=10
    )


if __name__ == "__main__":
    main()