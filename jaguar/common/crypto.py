# -*- coding: utf-8 -*-
"""Cifrado autenticado Jaguar (canónico). Debe coincidir EXACTO con el
cifrado embebido en agente/agente.py: PBKDF2 -> keystream HMAC + Encrypt-then-MAC."""
import hashlib
import hmac
import os
import struct

CLAVE_MAESTRA = b"J4GU4R-2026-clave-compartida"
SAL = b"jaguar-v1"
ITERACIONES = 100_000
_TAM_NONCE = 16
_TAM_MAC = 32

_CI = None
_MA = None


def _cinit():
    global _CI, _MA
    if _CI is None:
        m = hashlib.pbkdf2_hmac("sha256", CLAVE_MAESTRA, SAL, ITERACIONES, dklen=64)
        _CI, _MA = m[:32], m[32:]


def _keystream(nonce, n):
    _cinit()
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hmac.new(_CI, nonce + struct.pack(">Q", c), hashlib.sha256).digest()
        c += 1
    return bytes(out[:n])


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cifrar(datos, clave=None):
    _cinit()
    if isinstance(datos, str):
        datos = datos.encode("utf-8")
    pad = os.urandom(os.urandom(1)[0])
    cuerpo = struct.pack(">H", len(pad)) + pad + datos
    nonce = os.urandom(_TAM_NONCE)
    ct = _xor(cuerpo, _keystream(nonce, len(cuerpo)))
    mac = hmac.new(_MA, nonce + ct, hashlib.sha256).digest()
    return nonce + ct + mac


def descifrar(blob, clave=None):
    _cinit()
    if len(blob) < _TAM_NONCE + _TAM_MAC + 2:
        raise ValueError("trama corta")
    nonce, ct, mac = blob[:_TAM_NONCE], blob[_TAM_NONCE:-_TAM_MAC], blob[-_TAM_MAC:]
    if not hmac.compare_digest(mac, hmac.new(_MA, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("MAC inválido")
    cuerpo = _xor(ct, _keystream(nonce, len(ct)))
    return cuerpo[2 + struct.unpack(">H", cuerpo[:2])[0]:]