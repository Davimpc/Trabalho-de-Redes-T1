import threading, time, random, os
from ftplib import FTP
import requests

SERVER_IP = "192.168.0.219" 
HTTP_PORT = 8080
FTP_PORT = 2121

def http_worker(id):
    url = f"http://{SERVER_IP}:{HTTP_PORT}/"
    while True:
        try:
            r = requests.get(url, timeout=3)
            # também tentar uma rota inexistente para produzir 404s
            _ = requests.get(url + "nonexistent", timeout=3)
            print(f"[HTTP {id}] status {r.status_code}")
        except Exception as e:
            print(f"[HTTP {id}] erro {e}")
        time.sleep(random.uniform(0.2, 1.5))

def ftp_worker(id):
    while True:
        try:
            ftp = FTP()
            ftp.connect(SERVER_IP, FTP_PORT, timeout=5)
            ftp.login("user", "12345")
            # listagem
            ftp.retrlines('LIST')
            # subir e baixar um pequeno arquivo
            fname = f"tmp_client_{id}.txt"
            with open(fname, "w") as f:
                f.write("hello from client %d\n" % id)
            with open(fname, "rb") as f:
                ftp.storbinary("STOR " + fname, f)
            # baixar de volta
            with open("dl_" + fname, "wb") as f:
                ftp.retrbinary("RETR " + fname, f.write)
            ftp.quit()
            # cleanup local
            try:
                os.remove(fname)
                os.remove("dl_" + fname)
            except:
                pass
            print(f"[FTP {id}] transfer ok")
        except Exception as e:
            print(f"[FTP {id}] erro {e}")
        time.sleep(random.uniform(0.5, 2.0))

def start_simulation(n_clients=5):
    threads = []
    for i in range(n_clients):
        t1 = threading.Thread(target=http_worker, args=(i+1,), daemon=True)
        t2 = threading.Thread(target=ftp_worker, args=(i+1,), daemon=True)
        t1.start(); t2.start()
        threads.extend([t1, t2])
    # mantém o processo vivo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Parando simulação...")

if __name__ == "__main__":
    start_simulation(5)