# -*- coding: utf-8 -*-
"""Geolocalización (ip-api.com) + bandera emoji."""
import ipaddress
import json
import urllib.request

_CACHE = {}


def _privada(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def geolocalizar(ip):
    if not ip:
        return {}
    if ip in _CACHE:
        return _CACHE[ip]
    if _privada(ip):
        d = {"cc": "", "pais": "Local/LAN", "isp": "Red interna",
             "ciudad": "", "lat": 0, "lon": 0}
        _CACHE[ip] = d
        return d
    try:
        url = (f"http://ip-api.com/json/{ip}?fields=status,country,"
               f"countryCode,city,isp,lat,lon,regionName")
        with urllib.request.urlopen(url, timeout=6) as r:
            j = json.loads(r.read().decode())
        if j.get("status") != "success":
            return {}
        d = {"cc": j.get("countryCode", ""), "pais": j.get("country", ""),
             "isp": j.get("isp", ""), "ciudad": j.get("city", ""),
             "region": j.get("regionName", ""), "lat": j.get("lat", 0),
             "lon": j.get("lon", 0)}
        _CACHE[ip] = d
        return d
    except Exception:
        return {}


def bandera(cc):
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())