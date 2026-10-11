# -*- coding: utf-8 -*-
"""Registro central de sesiones activas. Thread-safe."""

import threading


class GestorClientes:
    def __init__(self):
        self._sesiones = {}
        self._lock = threading.Lock()

    def agregar(self, sesion):
        with self._lock:
            self._sesiones[sesion.cid] = sesion

    def obtener(self, cid):
        with self._lock:
            return self._sesiones.get(cid)

    def quitar(self, cid):
        with self._lock:
            return self._sesiones.pop(cid, None)

    def todos(self):
        with self._lock:
            return list(self._sesiones.values())

    def contar(self):
        with self._lock:
            return len(self._sesiones)