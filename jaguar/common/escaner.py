# -*- coding: utf-8 -*-
"""Escaneo de red/puertos con sockets (nmap opcional). Multiplataforma."""
import ipaddress
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

ES_WIN = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000


def _sc():
    return {"creationflags": CREATE_NO_WINDOW} if ES_WIN else {}


PUERTOS_COMUNES = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123,
                   135, 137, 138, 139, 143, 161, 389, 443, 445, 464, 500, 512,
                   513, 514, 587, 636, 873, 990, 993, 995, 1025, 1080, 1099,
                   1433, 1434, 1521, 1701, 1723, 1900, 2049, 2082, 2083, 2181,
                   2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4444, 4848,
                   5000, 5432, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
                   7001, 7002, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888,
                   9000, 9042, 9090, 9092, 9200, 9300, 9418, 10000, 11211,
                   15672, 27017, 27018, 50000, 50070, 61616]
_SERVICIOS = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
              53: "dns", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
              135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
              143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
              464: "kpasswd", 587: "smtp-sub", 636: "ldaps", 873: "rsync",
              993: "imaps", 995: "pop3s", 1080: "socks", 1099: "java-rmi",
              1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
              2376: "docker-tls", 3000: "node/gitea", 3306: "mysql", 3389: "rdp",
              3690: "svn", 4444: "msf-handler", 5000: "upnp/flask", 5432: "postgres",
              5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb",
              5985: "winrm", 5986: "winrm-tls", 6379: "redis", 7001: "weblogic",
              8080: "http-alt", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
              9000: "php-fpm", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
              9418: "git", 11211: "memcached", 15672: "rabbitmq-mgmt",
              27017: "mongodb", 27018: "mongodb", 50070: "hdfs", 61616: "activemq"}


def ip_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def detectar_subred():
    try:
        return str(ipaddress.ip_network(ip_local() + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


def _expandir_objetivo(objetivo):
    """Acepta '192.168.1.0/24', '192.168.1.10-50' y '192.168.1.10-192.168.1.50'."""
    objetivo = (objetivo or "").strip()
    if not objetivo:
        return [ip_local()]
    if "/" in objetivo:
        try:
            return [str(h) for h in ipaddress.ip_network(objetivo, strict=False).hosts()]
        except Exception:
            return [objetivo]
    if "-" in objetivo and "." in objetivo:
        ini, _, fin = objetivo.partition("-")
        ini, fin = ini.strip(), fin.strip()
        base = ini.rsplit(".", 1)[0]
        try:
            a = int(ini.rsplit(".", 1)[1])
            b = int(fin.rsplit(".", 1)[1]) if "." in fin else int(fin)
            if b >= a:
                return [f"{base}.{i}" for i in range(a, b + 1)]
        except Exception:
            pass
    return [objetivo]


def _expandir_puertos(puertos):
    puertos = (puertos or "").strip()
    if not puertos:
        return PUERTOS_COMUNES
    salida = []
    for parte in puertos.split(","):
        parte = parte.strip()
        if "-" in parte:
            try:
                a, b = parte.split("-")
                salida += list(range(int(a), int(b) + 1))
            except Exception:
                pass
        elif parte.isdigit():
            salida.append(int(parte))
    return salida or PUERTOS_COMUNES


def _probar(ip, puerto):
    s = socket.socket()
    s.settimeout(0.6)
    try:
        if s.connect_ex((ip, puerto)) != 0:
            return None
        banner = ""
        try:
            s.settimeout(0.4)
            banner = s.recv(128).decode("utf-8", "replace").strip()
        except Exception:
            pass
        return {"puerto": puerto, "servicio": _SERVICIOS.get(puerto, "?"), "banner": banner}
    finally:
        s.close()


def _ping(ip):
    """Ping multiplataforma."""
    cmd = (["ping", "-n", "1", "-w", "700", ip] if ES_WIN
           else ["ping", "-c", "1", "-W", "1", ip])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, **_sc())
        return r.returncode == 0
    except Exception:
        return True


def escanear(objetivo, puertos="", progreso=None, usar_nmap=True):
    hosts = _expandir_objetivo(objetivo)
    lista_puertos = _expandir_puertos(puertos)

    if usar_nmap and shutil.which("nmap"):
        try:
            return _escanear_nmap(objetivo, lista_puertos, progreso)
        except Exception:
            pass

    resultado = []
    total = max(1, len(hosts))
    for i, ip in enumerate(hosts):
        abiertos = []
        with ThreadPoolExecutor(max_workers=128) as ex:
            for r in ex.map(lambda p: _probar(ip, p), lista_puertos):
                if r:
                    abiertos.append(r)
        if abiertos:
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = ""
            resultado.append({"ip": ip, "host": host, "puertos": abiertos})
        if progreso:
            progreso(int((i + 1) / total * 100))
    return resultado


def _escanear_nmap(objetivo, puertos, progreso):
    rango = ",".join(str(p) for p in puertos)
    r = subprocess.run(["nmap", "-sV", "-Pn", "--open", "-p", rango, objetivo],
                       capture_output=True, text=True, **_sc())
    resultado = []
    ip_actual = None
    for linea in r.stdout.splitlines():
        if linea.startswith("Nmap scan report for "):
            resto = linea.replace("Nmap scan report for ", "").strip()
            if "(" in resto:
                host, ip = resto.split("(")
                ip_actual = ip.rstrip(")").strip()
                host = host.strip()
            else:
                ip_actual, host = resto, ""
            resultado.append({"ip": ip_actual, "host": host, "puertos": []})
        elif "/tcp" in linea and "open" in linea and resultado:
            campos = linea.split()
            try:
                puerto = int(campos[0].split("/")[0])
            except Exception:
                continue
            resultado[-1]["puertos"].append(
                {"puerto": puerto, "servicio": campos[2] if len(campos) > 2 else "?",
                 "banner": " ".join(campos[3:])})
    if progreso:
        progreso(100)
    return [h for h in resultado if h["puertos"]]