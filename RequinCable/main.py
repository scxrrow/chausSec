#!/usr/bin/python3

from scapy.all import sniff


def packet_callback(packet):
    print(packet.summary())


def main():
    sniff(
        prn=packet_callback,
        store=False,
        count=10
    )


if __name__ == "__main__":
    main()