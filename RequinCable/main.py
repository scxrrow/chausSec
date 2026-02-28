#!/usr/bin/python3
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

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

    src_port = dst_port = None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    if transport is not None:
        src_port = int(transport.sport)
        dst_port = int(transport.dport)

    if src_port is not None and dst_port is not None:
        print(f"{src}:{src_port} -> {dst}:{dst_port} ({protocol})")
    else:
        print(f"{src} -> {dst} ({protocol})")


def main():
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    main()