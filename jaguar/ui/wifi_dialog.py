# -*- coding: utf-8 -*-
"""wifi_dialog.py — ventana de Wi-Fi ofensivo (802.11) sobre wifi_ofensivo.

Toda operacion pesada corre en un hilo; el dialogo solo pinta.
Linux nativo o Windows->WSL2 (el backend lo autodetecta wifi_ofensivo).
"""
import os
import threading

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QSpinBox, QPlainTextEdit, QTreeWidget, QTreeWidgetItem, QGroupBox,
    QMessageBox, QFileDialog,
)

from jaguar.ui.theme import aplicar_tema_rojo_negro, ESTILO_BOTON
from jaguar.common import wifi_ofensivo as wf


class WifiOfensivoDialog(QDialog):
    _sig_log = pyqtSignal(str)
    _sig_aps = pyqtSignal(list)
    _sig_ifaces = pyqtSignal(list)
    _sig_words = pyqtSignal(list)
    _sig_fin = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Wi-Fi ofensivo — 802.11 (modo monitor)")
        self.resize(1100, 780)
        aplicar_tema_rojo_negro(self)

        self._iface = None
        self._mon = None
        self._aps = []
        self._ocupado = False

        self._sig_log.connect(self._log)
        self._sig_aps.connect(self._pintar_aps)
        self._sig_ifaces.connect(self._poner_ifaces)
        self._sig_words.connect(self._poner_words)
        self._sig_fin.connect(self._fin)

        self._build()
        self._diag()

    # =============================================================== UI
    def _build(self):
        l = QVBoxLayout(self)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(8)

        self.lbl_estado = QLabel("comprobando herramientas...")
        self.lbl_estado.setStyleSheet("color:#ffb84d;font-weight:700;")
        l.addWidget(self.lbl_estado)

        g = QGroupBox("Interfaz y captura")
        gl = QHBoxLayout(g)
        gl.addWidget(QLabel("Interfaz:"))
        self.cb_iface = QComboBox()
        self.cb_iface.setMinimumWidth(160)
        gl.addWidget(self.cb_iface)
        b_ref = QPushButton("⟳ Listar")
        b_ref.setStyleSheet(ESTILO_BOTON)
        b_ref.clicked.connect(self._pedir_ifaces)
        gl.addWidget(b_ref)
        self.btn_mon = QPushButton("📡 Activar monitor")
        self.btn_mon.setStyleSheet(ESTILO_BOTON)
        self.btn_mon.clicked.connect(self._toggle_monitor)
        gl.addWidget(self.btn_mon)
        gl.addWidget(QLabel("Segundos:"))
        self.sp_seg = QSpinBox()
        self.sp_seg.setRange(5, 120)
        self.sp_seg.setValue(15)
        self.sp_seg.setFixedWidth(70)
        gl.addWidget(self.sp_seg)
        b_scan = QPushButton("🔍 Escanear APs")
        b_scan.setStyleSheet(ESTILO_BOTON)
        b_scan.clicked.connect(self._escanear)
        gl.addWidget(b_scan)
        gl.addStretch()
        l.addWidget(g)

        self.tabla = QTreeWidget()
        self.tabla.setHeaderLabels(["ESSID", "BSSID", "Canal", "Señal",
                                    "Cifrado", "WPS", "Banda", "Seguridad"])
        self.tabla.setColumnWidth(0, 220)
        self.tabla.setColumnWidth(1, 150)
        self.tabla.setAlternatingRowColors(True)
        self.tabla.setRootIsDecorated(False)
        l.addWidget(self.tabla, 1)

        g2 = QGroupBox("Ataque al AP seleccionado")
        g2l = QHBoxLayout(g2)
        g2l.addWidget(QLabel("Diccionario:"))
        self.cb_word = QComboBox()
        self.cb_word.setMinimumWidth(260)
        g2l.addWidget(self.cb_word)
        b_w = QPushButton("📁")
        b_w.setFixedWidth(34)
        b_w.setStyleSheet(ESTILO_BOTON)
        b_w.clicked.connect(self._elegir_wordlist)
        g2l.addWidget(b_w)
        self.btn_atacar = QPushButton("⚔ Atacar (PMKID → handshake → hashcat)")
        self.btn_atacar.setStyleSheet(ESTILO_BOTON)
        self.btn_atacar.clicked.connect(self._atacar)
        g2l.addWidget(self.btn_atacar)
        b_best = QPushButton("⭐ Mejor AP")
        b_best.setStyleSheet(ESTILO_BOTON)
        b_best.clicked.connect(self._mejor)
        g2l.addWidget(b_best)
        g2l.addStretch()
        l.addWidget(g2)

        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFixedHeight(200)
        self.out.setStyleSheet("background:#0b0b0d;color:#ff5c5c;"
                               "font-family:Consolas;")
        l.addWidget(self.out)

    # ============================================================ helpers
    def _log(self, t):
        self.out.appendPlainText(str(t))

    def _hilo(self, fn):
        if self._ocupado:
            return
        self._ocupado = True
        self.btn_mon.setEnabled(False)
        self.btn_atacar.setEnabled(False)

        def _w():
            try:
                fn()
            except Exception as e:
                self._sig_log.emit(f"[error] {e}")
            finally:
                self._sig_fin.emit()
        threading.Thread(target=_w, daemon=True).start()

    def _fin(self):
        self._ocupado = False
        self.btn_mon.setEnabled(True)
        self.btn_atacar.setEnabled(True)

    def _poner_ifaces(self, ifaces):
        self.cb_iface.clear()
        for i in ifaces:
            self.cb_iface.addItem(i)
        if not ifaces:
            self._log("[!] sin interfaces inalambricas")

    def _poner_words(self, dics):
        self.cb_word.clear()
        for d in dics:
            self.cb_word.addItem(d)

    def _pedir_ifaces(self):
        self._hilo(lambda: self._sig_ifaces.emit(wf.interfaces() or []))

    def _elegir_wordlist(self):
        ruta, _ = QFileDialog.getOpenFileName(self, "Diccionario")
        if ruta:
            self.cb_word.addItem(ruta)
            self.cb_word.setCurrentText(ruta)

    # =========================================================== acciones
    def _diag(self):
        def _w():
            self._sig_log.emit(f"[backend] {wf.backend()}")
            self._sig_log.emit(wf.resumen_herramientas())
            faltan = wf.esenciales_faltan()
            if faltan:
                self._sig_log.emit("[!] faltan esenciales: " + ", ".join(faltan))
            self._sig_log.emit(wf.diagnostico())
            self._sig_ifaces.emit(wf.interfaces() or [])
            self._sig_words.emit(wf.diccionarios() or [])
        self._hilo(_w)

    def _toggle_monitor(self):
        if self._mon:
            mon, base = self._mon, self._iface

            def _w():
                self._sig_log.emit(wf.monitor_off(mon, base))
                self._sig_log.emit(wf.restaurar_red(base))
                self._mon = None
                self._sig_log.emit("[ok] monitor desactivado")
            self._hilo(_w)
            self.btn_mon.setText("📡 Activar monitor")
            return
        iface = self.cb_iface.currentText().strip()
        if not iface:
            QMessageBox.information(self, "Wi-Fi", "Elige una interfaz.")
            return
        self._iface = iface

        def _w():
            mon = wf.monitor_on(iface)
            if not mon:
                self._sig_log.emit("[!] no se pudo activar modo monitor")
                return
            self._mon = mon
            self._sig_log.emit(f"[ok] monitor activo en {mon}")
            self.btn_mon.setText(f"⏹ Quitar monitor ({mon})")
        self._hilo(_w)

    def _escanear(self):
        iface = self._mon or self.cb_iface.currentText().strip()
        if not iface:
            QMessageBox.information(self, "Wi-Fi", "Elige una interfaz.")
            return
        seg = self.sp_seg.value()

        def _w():
            self._sig_log.emit(f"[*] escaneando {seg}s en {iface}...")
            aps = wf.escanear(iface, seg) or []
            self._aps = aps
            self._sig_aps.emit(aps)
            self._sig_log.emit(f"[ok] {len(aps)} AP(s)")
        self._hilo(_w)

    def _pintar_aps(self, aps):
        self.tabla.clear()
        for a in aps:
            QTreeWidgetItem(self.tabla, [
                a.get("essid") or "(oculto)", a.get("bssid", ""),
                str(a.get("canal", "")), str(a.get("senal", "")),
                str(a.get("cifrado", "")), "sí" if a.get("wps") else "",
                str(a.get("banda", "")), str(a.get("seguridad", ""))])

    def _ap_sel(self):
        it = self.tabla.currentItem()
        if not it:
            return None
        bssid = it.text(1)
        for a in self._aps:
            if a.get("bssid") == bssid:
                return a
        return None

    def _mejor(self):
        ap = wf.mejor_ap(self._aps, solo_cifradas=True)
        if not ap:
            QMessageBox.information(self, "Wi-Fi", "Escanea primero.")
            return
        for i in range(self.tabla.topLevelItemCount()):
            if self.tabla.topLevelItem(i).text(1) == ap.get("bssid"):
                self.tabla.setCurrentItem(self.tabla.topLevelItem(i))
                break
        self._log(f"[*] mejor AP: {ap.get('essid')} {ap.get('bssid')} "
                  f"{ap.get('senal')}dBm {ap.get('seguridad')}")

    def _atacar(self):
        if not self._mon:
            QMessageBox.information(self, "Wi-Fi", "Activa el modo monitor primero.")
            return
        ap = self._ap_sel()
        if not ap:
            QMessageBox.information(self, "Wi-Fi", "Selecciona un AP de la tabla.")
            return
        word = self.cb_word.currentText().strip()
        if not word or not os.path.isfile(word):
            QMessageBox.information(self, "Wi-Fi", "Elige un diccionario válido.")
            return
        mon, iface = self._mon, self._iface

        def _w():
            psk, informe = wf.auto_atacar(
                mon, iface, ap, word, log=lambda t: self._sig_log.emit(str(t)))
            if informe:
                self._sig_log.emit(informe)
            self._sig_log.emit(f"[RESULTADO] PSK = {psk}" if psk
                               else "[RESULTADO] sin PSK")
        self._hilo(_w)