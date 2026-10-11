# -*- coding: utf-8 -*-
"""Framing auxiliar [4B longitud][payload cifrado]. Mismo esquema que el agente."""
import json
import socket
import struct

from jaguar.common.constants import TAM_LONGITUD
from jaguar.common import cripto


class ErrorProtocolo(Exception):
    pass


def _leer_exacto(sock, n):
    buf = bytearray()
    while len(buf) < n:
        trozo = sock.recv(n - len(buf))
        if not trozo:
            raise ConnectionError("conexión cerrada")
        buf.extend(trozo)
    return bytes(buf)


def enviar(sock, mensaje):
    crudo = json.dumps(mensaje, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cifrado = cripto.cifrar(crudo)
    sock.sendall(struct.pack(">I", len(cifrado)) + cifrado)


def recibir(sock):
    (n,) = struct.unpack(">I", _leer_exacto(sock, TAM_LONGITUD))
    if n == 0 or n > 64 * 1024 * 1024:
        raise ErrorProtocolo(f"longitud inválida: {n}")
    crudo = cripto.descifrar(_leer_exacto(sock, n))
    return json.loads(crudo.decode("utf-8"))