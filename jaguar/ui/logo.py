# -*- coding: utf-8 -*-
from PyQt6.QtCore import Qt, QRect
from PyQt6.QtGui import QPixmap, QPainter, QColor, QIcon, QFont, QPen


def obtener_logo(tam=64):
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


def obtener_icono():
    return QIcon(obtener_logo(64))