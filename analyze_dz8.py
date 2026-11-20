from scapy.all import rdpcap, Raw, TCP, IP
from urllib.parse import unquote
import gzip

PCAP = "dz8.pcap"

MARKS = (b"alert(", b"<script", b"onmouseover", b"onload=")

requests = 0
responses = 0
xss_requests = 0
xss_responses = 0
bufs = {}


def split_http(data):
    """отделяет тело ответа от заголовков, gzip распаковывает"""
    head, _, body = data.partition(b"\r\n\r\n")
    if b"gzip" in head.lower():
        try:
            body = gzip.decompress(body)
        except OSError:
            pass  # тело пришло не полностью или не сжато
    return head, body


def find_mark(data):
    """возвращает первый найденный признак и позицию в данных"""
    low = data.lower()
    for m in MARKS:
        i = low.find(m)
        if i >= 0:
            return m.decode(), i
    return None, -1


def handle_request(data):
    """печатает запросы с payload в стартовой строке"""
    global requests, xss_requests
    requests += 1
    first = data.split(b"\r\n", 1)[0].decode(errors="ignore")
    # пэйлоад в URL закодирован, ищем по декодированной строке
    mark, i = find_mark(unquote(first).encode())
    if mark:
        xss_requests += 1
        print()
        print("[XSS-запрос]", first[:90])
        if "?" in first:
            path, params = first.split("?", 1)
            print("    путь:", path[:70])
            print("    параметр:", params[:90])


def handle_response(data):
    """печатает ответы, в теле которых отражается пэйлоад"""
    global responses, xss_responses
    responses += 1
    head, body = split_http(data)
    mark, i = find_mark(body)
    if mark:
        xss_responses += 1
        code = head.split(b"\r\n", 1)[0].decode(errors="ignore")
        print()
        print("[XSS-ответ]", code, "| признак:", mark)
        frag = body[max(0, i - 50):i + 70]
        print("    отражение:", frag.decode(errors="ignore")[:110])


def flush(key):
    """обрабатывает накопленное сообщение и убирает буфер"""
    data = bufs.pop(key, None)
    if not data:
        return
    if data.startswith((b"GET", b"POST")):
        handle_request(data)
    elif data.startswith(b"HTTP/"):
        handle_response(data)


print("Анализ файла", PCAP)
for p in rdpcap(PCAP):
    if not p.haslayer(Raw) or not p.haslayer(TCP):
        continue
    key = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
    data = bytes(p[Raw].load)
    if data.startswith((b"GET", b"POST", b"HTTP/")):
        # старый буфер этого направления готов
        flush(key)
        bufs[key] = data
    elif key in bufs:
        # продолжение тела предыдущего сообщения
        bufs[key] += data

for key in list(bufs):
    flush(key)

print()
print("Всего HTTP-запросов:", requests, "| с payload:", xss_requests)
print("Всего HTTP-ответов:", responses, "| отражают payload:", xss_responses)
