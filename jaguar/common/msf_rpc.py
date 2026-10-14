# -*- coding: utf-8 -*-
"""msf_rpc.py — cliente Metasploit RPC (msfrpcd) para JAGUAR.
Requiere: pip install msgpack   (lado CONTROLADOR)

Arranque del server:
    msfrpcd -P tu_clave -S -a 127.0.0.1 -p 55552
"""
import http.client
import socket

try:
    import msgpack
except ImportError:
    msgpack = None


class MsfError(Exception):
    pass


class MsfRpc:
    def __init__(self, host="127.0.0.1", port=55552, usuario="msf",
                 password="", ssl=False):
        if msgpack is None:
            raise MsfError("falta msgpack: pip install msgpack")
        self.host = host
        self.port = int(port)
        self.usuario = usuario
        self.password = password
        self.ssl = ssl
        self.token = None
        self._ssl_auto = False

    def _conexion(self, usar_ssl):
        if usar_ssl or self.ssl or self._ssl_auto:
            return http.client.HTTPSConnection(self.host, self.port, timeout=60)
        return http.client.HTTPConnection(self.host, self.port, timeout=60)

    def _unpack(self, datos):
        try:
            return msgpack.unpackb(datos, raw=False)
        except TypeError:
            return msgpack.unpackb(datos, encoding="utf-8")

    def _call(self, metodo, *args):
        peticion = [metodo, self.token] + list(args)
        cuerpo = msgpack.packb(peticion, use_bin_type=True)
        ultimo_error = None
        for intento in range(2):
            usar_ssl = self.ssl or self._ssl_auto
            try:
                c = self._conexion(usar_ssl)
                try:
                    c.request("POST", "/api/", body=cuerpo,
                              headers={"Content-Type": "binary/message-pack"})
                    r = c.getresponse()
                    datos = r.read()
                finally:
                    c.close()
                try:
                    resp = self._unpack(datos)
                except Exception:
                    resp = None
                if not isinstance(resp, dict):
                    if intento == 0 and not usar_ssl:
                        self._ssl_auto = True
                        continue
                    raise MsfError("respuesta RPC ilegible (¿HTTP vs HTTPS?)")
                if resp.get("error"):
                    raise MsfError(str(resp["error"]))
                if resp.get("token"):
                    self.token = resp["token"]
                return resp.get("result", resp)
            except MsfError:
                raise
            except (OSError, socket.timeout) as e:
                ultimo_error = MsfError(
                    f"servidor caído o puerto cerrado en {self.host}:{self.port} ({e})")
                if intento == 0 and not usar_ssl:
                    self._ssl_auto = True
                    continue
            except http.client.HTTPException as e:
                ultimo_error = MsfError(f"error HTTP: {e}")
                if intento == 0 and not usar_ssl:
                    self._ssl_auto = True
                    continue
        raise ultimo_error or MsfError("fallo de conexión")

    # ---------------------------------------------------------------- API alta
    def login(self):
        self.token = self._call("auth.login", self.usuario, self.password)
        return self.token

    def version(self):
        return self._call("core.version")

    def sesiones(self):
        return self._call("session.list")

    def modulos(self, tipo="exploit"):
        metodo = {
            "exploit": "module.exploits",
            "auxiliary": "module.auxiliary",
            "post": "module.post",
            "payload": "module.payloads",
            "encoder": "module.encoders",
            "nop": "module.nops",
        }.get(tipo, "module.exploits")
        r = self._call(metodo)
        if isinstance(r, dict) and "modules" in r:
            return r["modules"]
        return r or []

    def buscar(self, termino):
        r = self._call("module.search", termino)
        if isinstance(r, dict) and "modules" in r:
            return r["modules"]
        return r or []

    def info_modulo(self, tipo, nombre):
        return self._call("module.info", tipo, nombre)

    def opciones_modulo(self, tipo, nombre):
        return self._call("module.options", tipo, nombre)

    def ejecutar_modulo(self, tipo, nombre, opciones=None):
        return self._call("module.execute", tipo, nombre, opciones or {})

    def lanzar_exploit(self, nombre, opciones=None):
        return self.ejecutar_modulo("exploit", nombre, opciones)

    def trabajos(self):
        return self._call("job.list")

    def matar_trabajo(self, jid):
        return self._call("job.stop", jid)

    def sesion_leer(self, sid):
        return self._call("session.shell_read", sid)

    def sesion_escribir(self, sid, datos):
        return self._call("session.shell_write", sid, datos)

    def consola_crear(self):
        return self._call("console.create")

    def consola_escribir(self, cid, comando):
        return self._call("console.write", cid, comando + "\n")

    def consola_leer(self, cid):
        return self._call("console.read", cid)

    def generar_payload(self, modulo_payload, opciones=None):
        return self._call("module.execute", "payload", modulo_payload, opciones or {})