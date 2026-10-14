# -*- coding: utf-8 -*-
"""Logo/icono de Jaguar.

Usa una imagen real (jaguar.png / jaguar.ico) si existe; si no, dibuja el logo
vectorial de respaldo. Aplica el icono a nivel de aplicacion + AppUserModelID
para que la barra de tareas muestre el icono correcto (no el de Python).
"""
import os
import sys

from PyQt6.QtCore import Qt, QRect
from PyQt6.QtGui import QPixmap, QPainter, QColor, QIcon, QFont, QPen

_AQUI = os.path.dirname(os.path.abspath(__file__))
_RAIZ = os.path.dirname(os.path.dirname(_AQUI))
_CANDIDATOS = [
    os.path.join(_AQUI, "jaguar.ico"),
    os.path.join(_AQUI, "jaguar.png"),
    os.path.join(_AQUI, "logo.png"),
    os.path.join(_RAIZ, "img", "jaguar.ico"),
    os.path.join(_RAIZ, "img", "jaguar.png"),
    os.path.join(_RAIZ, "img", "logo.png"),
]


def _ruta_imagen():
    for c in _CANDIDATOS:
        if os.path.isfile(c):
            return c
    return None


def _logo_vectorial(tam=84):
    pm = QPixmap(tam, tam)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor("#0b0b0d"))
    p.setPen(QPen(QColor("#ff2b2b"), max(1, tam // 20)))
    p.drawRoundedRect(1, 1, tam - 2, tam - 2, tam // 6, tam // 6)
    p.setPen(QColor("#ff2b2b"))
    p.setFont(QFont("Segoe UI", int(tam * 0.55), QFont.Weight.Bold))
    p.drawText(QRect(0, 0, tam, tam), Qt.AlignmentFlag.AlignCenter, "J")
    p.end()
    return pm


def obtener_logo(tam=64):
    """Devuelve el logo escalado. Usa la imagen real si esta disponible."""
    ruta = _ruta_imagen()
    if ruta:
        pm = QPixmap(ruta)
        if not pm.isNull():
            return pm.scaled(tam, tam, Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
    return _logo_vectorial(tam)


def obtener_icono():
    """QIcon multi-resolucion para ventana/taskbar."""
    ruta = _ruta_imagen()
    if ruta and ruta.lower().endswith(".ico"):
        ic = QIcon(ruta)
        if not ic.isNull():
            return ic
    ic = QIcon()
    for t in (16, 24, 32, 48, 64, 128, 256):
        ic.addPixmap(obtener_logo(t))
    return ic


def aplicar_icono_app(app):
    """Fija el icono en la QApplication y el AppUserModelID de Windows."""
    try:
        app.setWindowIcon(obtener_icono())
    except Exception:
        pass
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "Jaguar.RAT.1")
        except Exception:
            pass