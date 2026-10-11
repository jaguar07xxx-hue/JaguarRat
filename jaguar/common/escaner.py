# -*- coding: utf-8 -*-
"""Escaneo de red/puertos con sockets (nmap opcional)."""
import ipaddress
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

PUERTOS_COMUNES = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433,
                   1521, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443]
_SERVICIOS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
              80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
              443: "https", 445: "smb", 1433: "mssql", 1521: "oracle",
              3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
              5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
              8443: "https-alt"}


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
    objetivo = (objetivo or "").strip()
    if not objetivo:
        return [ip_local()]
    if "/" in objetivo:
        return [str(h) for h in ipaddress.ip_network(objetivo, strict=False).hosts()]
    if "-" in objetivo and "." in objetivo:
        base, fin = objetivo.rsplit(".", 1)
        if "-" in fin:
            a, b = fin.split("-")
            return [f"{base}.{i}" for i in range(int(a), int(b) + 1)]
    return [objetivo]


def _expandir_puertos(puertos):
    puertos = (puertos or "").strip()
    if not puertos:
        return PUERTOS_COMUNES
    salida = []
    for parte in puertos.split(","):
        parte = parte.strip()
        if "-" in parte:
            a, b = parte.split("-")
            salida += list(range(int(a), int(b) + 1))
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
        with ThreadPoolExecutor(max_workers=64) as ex:
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
    r = subprocess.run(["nmap", "-sV", "-Pn", "-p", rango, objetivo],
                       capture_output=True, text=True)
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