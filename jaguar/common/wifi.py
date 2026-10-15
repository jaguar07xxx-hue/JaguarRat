# -*- coding: utf-8 -*-
"""wifi.py — descubrimiento Wi-Fi 802.11 (modo monitor). Linux + aircrack-ng.

Opcional: si no hay aircrack-ng, el escaner IP sigue funcionando igual.
"""
import csv
import glob
import os
import re
import shutil
import subprocess
import tempfile
import time


def hay_aircrack():
    return bool(shutil.which("airodump-ng") and shutil.which("airmon-ng"))


def interfaces():
    """Lista interfaces inalambricas."""
    if shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "dev"], capture_output=True,
                                 text=True, timeout=6).stdout
            devs = re.findall(r"Interface\s+(\S+)", out)
            if devs:
                return devs
        except Exception:
            pass
    try:
        out = subprocess.run(["airmon-ng"], capture_output=True,
                             text=True, timeout=6).stdout
        return [l.split()[0] for l in out.splitlines()[2:] if l.strip()]
    except Exception:
        return []


def poner_monitor(iface):
    """Activa modo monitor. Devuelve el nombre de la interfaz mon (ej. wlan0mon)."""
    try:
        r = subprocess.run(["airmon-ng", "start", iface], capture_output=True,
                           text=True, timeout=25)
        m = re.search(r"monitor mode.*?(\w+mon)", r.stdout)
        return m.group(1) if m else f"{iface}mon"
    except Exception:
        return None


def quitar_monitor(iface_mon):
    try:
        subprocess.run(["airmon-ng", "stop", iface_mon], capture_output=True,
                       text=True, timeout=25)
    except Exception:
        pass


def escanear(iface_mon, segundos=15):
    """Captura APs cercanos. Devuelve [{bssid, canal, senal, cifrado, essid}]."""
    prefijo = os.path.join(tempfile.gettempdir(), "jaguar_wifi")
    for f in glob.glob(prefijo + "*"):
        try:
            os.remove(f)
        except OSError:
            pass
    proc = subprocess.Popen(
        ["airodump-ng", "--output-format", "csv", "--write", prefijo, iface_mon],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(max(3, int(segundos)))
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    aps, en_ap = [], True
    for csvf in glob.glob(prefijo + "*.csv"):
        with open(csvf, encoding="utf-8", errors="replace") as f:
            for fila in csv.reader(f):
                if not fila:
                    continue
                if fila[0].strip().startswith("BSSID"):
                    continue
                if fila[0].strip().startswith("Station"):
                    en_ap = False
                    continue
                if not en_ap or len(fila) < 14 or not fila[0].strip():
                    continue
                aps.append({
                    "bssid": fila[0].strip(), "canal": fila[3].strip(),
                    "senal": fila[8].strip(), "cifrado": fila[5].strip(),
                    "essid": fila[13].strip(),
                })
    return aps