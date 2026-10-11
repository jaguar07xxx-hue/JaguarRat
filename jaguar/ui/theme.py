# -*- coding: utf-8 -*-
"""Tema rojo/negro Jaguar — estilo profesional tipo Quasar."""

from PyQt6.QtGui import QPalette, QColor, QFont

NEGRO = "#0b0b0d"
NEGRO_2 = "#121216"
PANEL = "#17171c"
PANEL_ALT = "#1e1e25"
ROJO = "#ff2b2b"
ROJO_OSC = "#b01010"
ROJO_CLARO = "#ff5c5c"
TEXTO = "#e8e8ea"
TENUE = "#8a8a92"
BORDE = "#2a2a33"

ESTILO_BOTON = f"""
QPushButton {{
    background-color: {PANEL_ALT};
    color: {ROJO};
    border: 1px solid {ROJO_OSC};
    border-radius: 5px;
    padding: 7px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background-color: {ROJO_OSC}; color: {TEXTO}; }}
QPushButton:pressed, QPushButton:checked {{ background-color: {ROJO}; color: #0b0b0d; }}
QPushButton:disabled {{ color: {TENUE}; border-color: {BORDE}; }}
"""

ESTILO_TABLA = f"""
QTreeWidget, QTableWidget {{
    background-color: {NEGRO_2};
    alternate-background-color: {PANEL};
    color: {TEXTO};
    gridline-color: {BORDE};
    selection-background-color: {ROJO_OSC};
    selection-color: {TEXTO};
    font-family: Consolas, monospace;
    border: 1px solid {BORDE};
}}
QHeaderView::section {{
    background-color: {PANEL_ALT};
    color: {ROJO};
    border: none;
    border-right: 1px solid {BORDE};
    padding: 6px;
    font-weight: 700;
}}
QTreeWidget::item, QTableWidget::item {{ height: 22px; }}
"""

ESTILO_GENERAL = f"""
QMainWindow, QDialog {{ background-color: {NEGRO}; }}
QWidget {{ color: {TEXTO}; font-family: 'Segoe UI', Arial; font-size: 10pt; }}
QGroupBox {{
    border: 1px solid {BORDE};
    border-radius: 6px;
    margin-top: 12px;
    padding: 10px 8px 8px 8px;
    color: {ROJO};
    font-weight: 700;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 5px; }}
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QComboBox {{
    background-color: {NEGRO_2};
    color: {TEXTO};
    border: 1px solid {BORDE};
    border-radius: 4px;
    padding: 5px;
    selection-background-color: {ROJO_OSC};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border: 1px solid {ROJO}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {PANEL}; color: {TEXTO}; selection-background-color: {ROJO_OSC}; }}
QMenu {{ background-color: {PANEL}; color: {TEXTO}; border: 1px solid {ROJO_OSC}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background-color: {ROJO_OSC}; }}
QMenuBar {{ background-color: {NEGRO_2}; color: {ROJO}; }}
QToolBar {{ background-color: {NEGRO_2}; border-bottom: 1px solid {BORDE}; spacing: 6px; padding: 4px; }}
QStatusBar {{ background-color: {NEGRO_2}; color: {TENUE}; }}
QSplitter::handle {{ background-color: {BORDE}; }}
QTabWidget::pane {{ border: 1px solid {BORDE}; top: -1px; }}
QTabBar::tab {{
    background: {PANEL};
    color: {TENUE};
    padding: 8px 18px;
    border: 1px solid {BORDE};
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    font-weight: 600;
}}
QTabBar::tab:selected {{ background: {ROJO_OSC}; color: {TEXTO}; }}
QTabBar::tab:hover {{ color: {ROJO}; }}
QScrollBar:vertical {{ background: {NEGRO}; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDE}; border-radius: 6px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {ROJO_OSC}; }}
QScrollBar:horizontal {{ background: {NEGRO}; height: 12px; }}
QScrollBar::handle:horizontal {{ background: {BORDE}; border-radius: 6px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ background: none; border: none; }}
QProgressBar {{ background: {NEGRO_2}; border: 1px solid {ROJO_OSC}; border-radius: 4px; text-align: center; color: {TEXTO}; }}
QProgressBar::chunk {{ background: {ROJO}; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border: 1px solid {ROJO_OSC}; border-radius: 3px; background: {NEGRO_2}; }}
QCheckBox::indicator:checked {{ background: {ROJO}; }}
"""


def aplicar_tema_rojo_negro(widget):
    """Aplica paleta + hoja de estilo al widget dado (o a la app)."""
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(NEGRO))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXTO))
    pal.setColor(QPalette.ColorRole.Base, QColor(NEGRO_2))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.Text, QColor(TEXTO))
    pal.setColor(QPalette.ColorRole.Button, QColor(PANEL_ALT))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(ROJO))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(ROJO_OSC))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(TEXTO))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXTO))
    widget.setPalette(pal)
    widget.setStyleSheet(ESTILO_GENERAL + ESTILO_BOTON + ESTILO_TABLA)
    return widget
# --- ajustes de layout denso (añadir al final del archivo) ---
EXTRA = f"""
QFrame#topbar {{ background: {NEGRO_2}; border-bottom: 1px solid {BORDE}; }}
QFrame#detalle {{ background: {PANEL}; border: 1px solid {BORDE}; border-radius: 6px; }}
QWidget#panel {{ background: {NEGRO}; }}
QTabWidget::pane {{ border: none; background: {NEGRO}; }}
QTabWidget > QWidget {{ background: {NEGRO}; }}
QTreeWidget {{ border: 1px solid {BORDE}; }}
QTreeWidget::item {{ height: 24px; padding-left: 4px; }}
QLineEdit {{ min-height: 22px; }}
"""
ESTILO_GENERAL += EXTRA