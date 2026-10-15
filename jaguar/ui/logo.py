# -*- coding: utf-8 -*-
"""Logo/icono de Jaguar — multirresolución, multiplataforma y con contraste.

- Carga jaguar.png (alta resolución) y la escala al tamaño pedido.
- Tamaño por defecto GRANDE (72 px) para que se vea.
- Genera QIcon con varios tamaños para ventana/taskbar.
- Fallback vectorial si no hay imagen (siempre se ve algo).
- generar_ico(): convierte el PNG en .ico multirresolución (Pillow).
"""
import os
import sys
from functools import lru_cache

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

TAMANOS_ICONO = (16, 24, 32, 48, 64, 128, 256)
TAM_LOGO_DEFECTO = 82          # GRANDE
TAM_LOGO_TOPBAR = 874           # tamaño que usa la barra superior
TAM_LOGO_GRANDE = 148          # para splash / "Acerca de"


def _ruta_imagen():
    for c in _CANDIDATOS:
        if os.path.isfile(c):
            return c
    return None


@lru_cache(maxsize=1)
def _pixmap_fuente():
    ruta = _ruta_imagen()
    if not ruta:
        return None
    pm = QPixmap(ruta)
    return pm if not pm.isNull() else None


def _logo_vectorial(tam):
    pm = QPixmap(tam, tam)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor("#0b0b0d"))
    p.setPen(QPen(QColor("#ff2b2b"), max(2, tam // 16)))
    p.drawRoundedRect(2, 2, tam - 4, tam - 4, tam // 6, tam // 6)
    p.setPen(QColor("#ff2b2b"))
    p.setFont(QFont("Segoe UI", int(tam * 0.58), QFont.Weight.Bold))
    p.drawText(QRect(0, 0, tam, tam), Qt.AlignmentFlag.AlignCenter, "J")
    p.end()
    return pm


def obtener_logo(tam=TAM_LOGO_DEFECTO):
    """Devuelve el logo al tamaño pedido. Nunca devuelve algo vacío."""
    base = _pixmap_fuente()
    if base is None:
        return _logo_vectorial(tam)
    return base.scaled(tam, tam, Qt.AspectRatioMode.KeepAspectRatio,
                       Qt.TransformationMode.SmoothTransformation)


def obtener_logo_topbar():
    return obtener_logo(TAM_LOGO_TOPBAR)


def obtener_logo_grande():
    return obtener_logo(TAM_LOGO_GRANDE)


def obtener_icono():
    """QIcon multirresolución para ventana y barra de tareas."""
    ruta = _ruta_imagen()
    if ruta and ruta.lower().endswith(".ico"):
        ic = QIcon(ruta)
        if not ic.isNull():
            return ic
    ic = QIcon()
    for t in TAMANOS_ICONO:
        ic.addPixmap(obtener_logo(t))
    return ic


def generar_ico(destino=None, origen=None):
    """Convierte una imagen (por defecto jaguar.png) en .ico multirresolución."""
    origen = origen or _ruta_imagen()
    if not origen or not os.path.isfile(origen) or origen.lower().endswith(".ico"):
        return origen
    try:
        from PIL import Image
    except ImportError:
        return None
    destino = destino or os.path.join(_AQUI, "jaguar.ico")
    Image.open(origen).convert("RGBA").save(
        destino, sizes=[(t, t) for t in TAMANOS_ICONO])
    return destino


def aplicar_icono_app(app):
    """Fija el icono en la QApplication y el AppUserModelID de Windows."""
    try:
        app.setWindowIcon(obtener_icono())
    except Exception:
        pass
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Jaguar.RAT.1")
        except Exception:
            pass