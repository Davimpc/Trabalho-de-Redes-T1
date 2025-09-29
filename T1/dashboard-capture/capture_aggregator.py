import time, threading, queue, logging, requests, json
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ------------- CONFIGURAÇÕES -------------
INTERFACE = "Ethernet"              # interface espelhada
SERVER_IP = "192.168.0.219"         # alvo (servidor)
API_ENDPOINT = "http://127.0.0.1:5000/api/traffic/aggregate"  # API
WINDOW_SIZE = 5                     # segundos para cada janela
BPF_FILTER = f"host {SERVER_IP}"    # captura só pacotes envolvendo o servidor
MAX_QUEUE = 10000
# -----------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
pkt_queue = queue.Queue(MAX_QUEUE)

windows = {}
windows_lock = threading.Lock()

def current_window_ts(ts=None):
    t = ts if ts else time.time()
    return int(t // WINDOW_SIZE) * WINDOW_SIZE

def classify_packet(pkt):
    """Retorna (client_ip, direction, proto_str, length) ou None se não for IP/útil."""
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    src, dst = ip.src, ip.dst

    length = int(ip.len) if getattr(ip, "len", None) else len(pkt)
    # direção dos pacotes
    if dst == SERVER_IP and src != SERVER_IP:
        client = src
        direction = "in"   # cliente -> servidor
    elif src == SERVER_IP and dst != SERVER_IP:
        client = dst
        direction = "out"  # servidor -> cliente
    else:
        return None  # tráfego não relacionado (broadcast, etc.)
    # protocolo
    if pkt.haslayer(TCP): proto = "TCP"
    elif pkt.haslayer(UDP): proto = "UDP"
    elif pkt.haslayer(ICMP): proto = "ICMP"
    else: proto = "OTHER"
    return client, direction, proto, length

def packet_handler(pkt):
    try:
        pkt_queue.put_nowait(pkt)
    except queue.Full:
        logging.warning("Queue cheia — pacote descartado")

def capture_thread():
    logging.info(f"Starting capture on {INTERFACE} filter='{BPF_FILTER}' (sudo needed)")
    sniff(iface=INTERFACE, filter=BPF_FILTER, prn=packet_handler, store=False)

def process_packet_obj(pkt):
    info = classify_packet(pkt)
    if not info:
        return
    client, direction, proto, length = info
    w_ts = current_window_ts()
    with windows_lock:
        if w_ts not in windows:
            windows[w_ts] = {}
        clients = windows[w_ts]
        if client not in clients:
            clients[client] = {"bytes_in": 0, "bytes_out": 0, "protocols": defaultdict(int)}
        entry = clients[client]
        if direction == "in":
            entry["bytes_in"] += length
        else:
            entry["bytes_out"] += length
        entry["protocols"][proto] += length

def aggregator_thread():
    while True:
        try:
            pkt = pkt_queue.get(timeout=1)
            process_packet_obj(pkt)
        except queue.Empty:
            continue
        except Exception as e:
            logging.exception("Erro no aggregador: %s", e)

def flush_window_payload(w_ts, data):
    # transformanr em JSON 
    clients_list = []
    for ip, stats in data.items():
        clients_list.append({
            "client_ip": ip,
            "bytes_in": stats["bytes_in"],
            "bytes_out": stats["bytes_out"],
            "protocols": dict(stats["protocols"])
        })
    payload = {
        "window_start": w_ts,
        "window_end": w_ts + WINDOW_SIZE,
        "server_ip": SERVER_IP,
        "clients": clients_list
    }
    for attempt in range(1,4):
        try:
            resp = requests.post(API_ENDPOINT, json=payload, timeout=5)
            if resp.status_code == 200 or resp.status_code == 201:
                logging.info(f"Enviei janela {w_ts} com {len(clients_list)} clientes.")
                return True
            else:
                logging.warning(f"API retornou {resp.status_code}: {resp.text}")
        except Exception as e:
            logging.warning(f"Erro ao enviar (tentativa {attempt}): {e}")
        time.sleep(attempt)
    logging.error(f"Falha ao enviar janela {w_ts} depois de retries.")
    return False

def flusher_thread():
    while True:
        time.sleep(1)
        now_w = current_window_ts()
        to_flush = []
        with windows_lock:
            for w_ts in list(windows.keys()):
                if w_ts < now_w:
                    to_flush.append((w_ts, windows.pop(w_ts)))
        for w_ts, data in to_flush:
            flush_window_payload(w_ts, data)

def main():
    tcap = threading.Thread(target=capture_thread, daemon=True)
    tagg = threading.Thread(target=aggregator_thread, daemon=True)
    tflush = threading.Thread(target=flusher_thread, daemon=True)
    tcap.start(); tagg.start(); tflush.start()
    logging.info("Capture + aggregator started. CTRL+C para parar.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Parando...")

if __name__ == "__main__":
    main()