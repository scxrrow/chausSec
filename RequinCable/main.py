#!/usr/bin/python3
from scapy.all import sniff
from scapy.layers.inet import IP

PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def packet_callback(packet):
    if IP not in packet:
        return

    ip = packet[IP]

    src = ip.src
    dst = ip.dst

    proto_num = int(ip.proto)
    protocol = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")

    print(f"{src} -> {dst} ({protocol})")


def main():
    sniff(
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":
    main()