# -*- coding: utf-8 -*-
"""Utilidades de red: IP pública/local, validación de LHOST/LPORT."""

import socket
import urllib.request

_SERVICIOS_IP = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ipinfo.io/ip",
]

_cache_publica = {"ip": None}


def ip_publica(timeout=4.0) -> str:
    """Detecta la IP pública. Cachea el resultado. Devuelve '' si falla."""
    if _cache_publica["ip"]:
        return _cache_publica["ip"]
    for url in _SERVICIOS_IP:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                ip = r.read().decode().strip()
            if _ip_valida(ip) and not _es_privada(ip):
                _cache_publica["ip"] = ip
                return ip
        except Exception:
            continue
    return ""


def ip_local() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _ip_valida(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return ip.count(".") == 3
    except Exception:
        return False


def _es_privada(ip: str) -> bool:
    octetos = ip.split(".")
    if len(octetos) != 4:
        return False
    a, b = int(octetos[0]), int(octetos[1])
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )


def lhost_defecto() -> str:
    """IP pública si hay internet; si no, IP local."""
    return ip_publica() or ip_local()


def validar_lport(puerto) -> int:
    try:
        p = int(puerto)
        if 1 <= p <= 65535:
            return p
    except Exception:
        pass
    return 4444