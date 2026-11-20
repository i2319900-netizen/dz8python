from scapy.all import sniff, wrpcap, Raw

captured = []


def print_packet(pkt):
    captured.append(pkt)
    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        # вывод http запросов
        if data.startswith((b"GET", b"POST", b"HTTP")):
            first = data.split(b"\r\n", 1)[0]
            print(first.decode(errors="ignore"))


print("Снифер запущен")
try:
    sniff(filter="tcp port 80", prn=print_packet, store=False)
except KeyboardInterrupt:
    pass

wrpcap("dz8.pcap", captured)
print("Сохранено:", len(captured), "пакетов -> dz8.pcap")
