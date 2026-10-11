# -*- coding: utf-8 -*-
"""Cripto Jaguar: PBKDF2-HMAC-SHA256 (derivación) + keystream XOR + HMAC-SHA256.
Idéntico al crypto embebido en agente.py — DEBE coincidir byte a byte."""
import hashlib
import hmac
import os
import struct

from jaguar.common.constants import CLAVE_XOR_DEFECTO

CLAVE_MAESTRA = CLAVE_XOR_DEFECTO     # b"J4GU4R-2026-clave-compartida"
SAL = b"jaguar-v1"
ITER = 100_000
_CI = None
_MA = None


def _init():
    global _CI, _MA
    if _CI is None:
        m = hashlib.pbkdf2_hmac("sha256", CLAVE_MAESTRA, SAL, ITER, dklen=64)
        _CI, _MA = m[:32], m[32:]


def _ks(nonce, n):
    _init()
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hmac.new(_CI, nonce + struct.pack(">Q", c), hashlib.sha256).digest()
        c += 1
    return bytes(out[:n])


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cifrar(datos):
    _init()
    if isinstance(datos, str):
        datos = datos.encode("utf-8")
    pad = os.urandom(os.urandom(1)[0])
    cuerpo = struct.pack(">H", len(pad)) + pad + datos
    nonce = os.urandom(16)
    ct = _xor(cuerpo, _ks(nonce, len(cuerpo)))
    mac = hmac.new(_MA, nonce + ct, hashlib.sha256).digest()
    return nonce + ct + mac


def descifrar(blob):
    _init()
    if len(blob) < 48:
        raise ValueError("trama corta")
    nonce, ct, mac = blob[:16], blob[16:-32], blob[-32:]
    if not hmac.compare_digest(mac, hmac.new(_MA, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("MAC inválido")
    cuerpo = _xor(ct, _ks(nonce, len(ct)))
    return cuerpo[2 + struct.unpack(">H", cuerpo[:2])[0]:]