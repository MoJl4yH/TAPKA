DARK_STYLE = """
* {
    font-family: "IBM Plex Sans", "Noto Sans", "Ubuntu", "Cantarell";
    font-size: 11pt;
    color: #e6e9ee;
}

QMainWindow#MainWindow {
    background-color: #121417;
}

QFrame#sidebar {
    background-color: #1b1f24;
    border: 1px solid #2b3138;
    border-radius: 16px;
}

QLabel#sidebarTitle {
    font-size: 16pt;
    font-weight: 600;
}

QLabel#headerTitle {
    font-size: 18pt;
    font-weight: 600;
}

QLabel#sectionTitle {
    font-size: 11pt;
    font-weight: 600;
}

QLabel#projectName {
    font-size: 14pt;
    font-weight: 600;
}

QLabel#statusBadge {
    background-color: #1f2a2d;
    color: #4db7b0;
    border-radius: 10px;
    padding: 4px 10px;
    font-weight: 600;
}

QLabel#muted {
    color: #9aa3ad;
}

QFrame#card {
    background-color: #1b1f24;
    border: 1px solid #2b3138;
    border-radius: 14px;
}

QFrame#metricCard {
    background-color: #20252b;
    border: 1px solid #2b3138;
    border-radius: 12px;
}

QLabel#metricTitle {
    font-size: 10pt;
    color: #9aa3ad;
}

QLabel#metricValue {
    font-size: 16pt;
    font-weight: 600;
}

QLineEdit,
QComboBox {
    background-color: #1b1f24;
    border: 1px solid #2f353d;
    border-radius: 10px;
    padding: 6px 10px;
    color: #e6e9ee;
}

QLineEdit:focus,
QComboBox:focus {
    border: 1px solid #4db7b0;
}

QListWidget,
QTableWidget,
QPlainTextEdit {
    background-color: #1b1f24;
    border: 1px solid #2b3138;
    border-radius: 12px;
    color: #e6e9ee;
}

QListWidget::item {
    padding: 10px;
    border-radius: 8px;
    color: #e6e9ee;
}

QListWidget::item:selected {
    background-color: #223236;
    color: #e6e9ee;
}

QTableWidget::item:selected {
    background-color: #223236;
}

QHeaderView::section {
    background-color: #1f242a;
    padding: 6px 8px;
    border: none;
    font-weight: 600;
    color: #e6e9ee;
}

QAbstractItemView {
    background-color: #1b1f24;
    color: #e6e9ee;
}

QTabWidget::pane {
    border: 1px solid #2b3138;
    border-radius: 12px;
    top: -1px;
}

QTabBar::tab {
    background: #1f242a;
    border: 1px solid #2b3138;
    border-bottom: none;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    padding: 6px 12px;
    margin-right: 4px;
}

QTabBar::tab:selected {
    background: #1b1f24;
}

QPushButton {
    background-color: #1b1f24;
    border: 1px solid #2f353d;
    border-radius: 10px;
    padding: 8px 14px;
}

QPushButton:hover {
    border-color: #4db7b0;
}

QPushButton#primaryButton {
    background-color: #4db7b0;
    color: #0d1a1b;
    border: 1px solid #4db7b0;
}

QPushButton#primaryButton:hover {
    background-color: #3fa29c;
}

QPushButton:disabled {
    background-color: #21262d;
    color: #7d8692;
    border-color: #2f353d;
}

QPushButton#toolStatus {
    border: none;
    background: transparent;
    padding: 0;
    text-align: left;
    color: #9aa3ad;
}

QPushButton#toolStatus[status="ok"] {
    color: #4db7b0;
}

QPushButton#toolStatus[status="fail"] {
    color: #ff7b7b;
}

QPushButton#toolStatus[status="partial"] {
    color: #f5a65b;
}

QPushButton#toolStatus[status="running"] {
    color: #d2b48c;
}

QProgressBar {
    background-color: #1f242a;
    border: 1px solid #2b3138;
    border-radius: 6px;
    text-align: center;
    height: 14px;
}

QProgressBar::chunk {
    background-color: #4db7b0;
    border-radius: 6px;
}

QScrollBar:vertical {
    background: #1f242a;
    width: 10px;
    margin: 0;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #3b424c;
    border-radius: 4px;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}
"""


def get_style() -> str:
    return DARK_STYLE


APP_STYLE = DARK_STYLE
