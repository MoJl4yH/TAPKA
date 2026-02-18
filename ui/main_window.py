from __future__ import annotations

import json
import time
import traceback
from pathlib import Path
from datetime import datetime
import re
from typing import Callable

from PySide6.QtCore import Qt, QUrl, QThread, Signal, QTimer
from PySide6.QtGui import QDesktopServices, QPixmap, QIcon
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QLabel,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QLineEdit,
    QFrame,
    QFileDialog,
    QMessageBox,
    QProgressBar,
    QTabWidget,
    QStackedWidget,
    QGridLayout,
    QFormLayout,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPlainTextEdit,
    QCheckBox,
    QSizePolicy,
    QInputDialog,
    QMenu,
)

from analysis.storage import Storage
from analysis.settings import load_settings, save_settings
from analysis.stages import STAGES, STAGE_CROSS_TOOL, STAGE_OVERALL, STAGE_STATIC
from analysis.stage1_analysis import Stage1StaticRunner
from analysis.mobsf import DEFAULT_MOBSF_URL, ensure_mobsf_ready, normalize_base_url, stop_mobsf
from analysis.mobsf.stage3_runner import Stage3Config, Stage3MobSFRunner
from analysis.apkid.stage3_runner import Stage3ApkidConfig, Stage3ApkidRunner
from analysis.apkleaks.stage3_runner import Stage3ApkleaksConfig, Stage3ApkleaksRunner
from analysis.quark.stage3_runner import Stage3QuarkConfig, Stage3QuarkRunner
from analysis.reporting import ReportManager
from analysis.reporting.stage3_html_report import render_report_html
from models import Project, Run, CommandResult
from models.report_v2 import ReportV2
from ui.style import get_style


class Stage1Worker(QThread):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(object)

    def __init__(self, storage: Storage, project_id: str):
        super().__init__()
        self.storage = storage
        self.project_id = project_id

    def run(self) -> None:
        runner = Stage1StaticRunner(self.storage, on_progress=self.progress.emit)
        try:
            run = runner.run(self.project_id)
            self.finished.emit(run)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())


class MobSFSetupWorker(QThread):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, base_url: str, api_key: str | None):
        super().__init__()
        self.base_url = base_url
        self.api_key = api_key

    def run(self) -> None:
        try:
            result = ensure_mobsf_ready(self.base_url, api_key=self.api_key, log=self.progress.emit)
            self.finished.emit(result)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())


class MobSFStopWorker(QThread):
    finished = Signal(bool)
    failed = Signal(str)
    progress = Signal(str)

    def run(self) -> None:
        try:
            stopped = stop_mobsf(log=self.progress.emit)
            self.finished.emit(stopped)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())


class Stage3Worker(QThread):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, storage: Storage, project_id: str, config: Stage3Config):
        super().__init__()
        self.storage = storage
        self.project_id = project_id
        self.config = config

    def run(self) -> None:
        runner = Stage3MobSFRunner(self.storage, config=self.config, on_progress=self.progress.emit)
        try:
            run = runner.run(self.project_id)
            self.finished.emit(run)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())


class Stage3QuarkWorker(QThread):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, storage: Storage, project_id: str, config: Stage3QuarkConfig):
        super().__init__()
        self.storage = storage
        self.project_id = project_id
        self.config = config

    def run(self) -> None:
        runner = Stage3QuarkRunner(self.storage, config=self.config, on_progress=self.progress.emit)
        try:
            run = runner.run(self.project_id)
            self.finished.emit(run)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())


class Stage3ApkidWorker(QThread):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, storage: Storage, project_id: str, config: Stage3ApkidConfig):
        super().__init__()
        self.storage = storage
        self.project_id = project_id
        self.config = config

    def run(self) -> None:
        runner = Stage3ApkidRunner(self.storage, config=self.config, on_progress=self.progress.emit)
        try:
            run = runner.run(self.project_id)
            self.finished.emit(run)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())


class Stage3ApkleaksWorker(QThread):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, storage: Storage, project_id: str, config: Stage3ApkleaksConfig):
        super().__init__()
        self.storage = storage
        self.project_id = project_id
        self.config = config

    def run(self) -> None:
        runner = Stage3ApkleaksRunner(self.storage, config=self.config, on_progress=self.progress.emit)
        try:
            run = runner.run(self.project_id)
            self.finished.emit(run)
        except Exception:  # pylint: disable=broad-exception-caught
            self.failed.emit(traceback.format_exc())
class MainWindow(QMainWindow):
    TOOL_STATUS_DEFS = [
        ("apksigner", "APK signature"),
        ("aapt2", "Manifest"),
        ("keytool", "Certificates"),
        ("apktool", "Resources"),
        ("jadx", "Decompile"),
        ("rg", "Pattern scan"),
        ("strings", "Native strings"),
        ("yara", "YARA scan"),
    ]
    SEVERITY_ORDER = ["High", "Medium", "Low", "Info"]
    CATEGORY_TITLE = {
        "url": "Endpoints",
        "ipv4": "IP Address",
        "sensitive_kv": "Secrets",
        "jwt": "JWT",
        "dynamic_loading": "Dynamic Loading",
        "anti_debug": "Anti-debug",
        "command_exec": "Command Execution",
        "root_paths": "Root Paths",
    }
    SEVERITY_MAP = {
        "sensitive_kv": "High",
        "jwt": "High",
        "dynamic_loading": "Medium",
        "command_exec": "Medium",
        "root_paths": "Medium",
        "anti_debug": "Low",
        "url": "Low",
        "ipv4": "Low",
    }
    ALLOWED_NONZERO_RETURN = {"rg": {1}, "grep": {1}}
    JADX_PARTIAL_PATTERN = re.compile(r"finished with errors", re.IGNORECASE)

    def __init__(self, storage: Storage):
        super().__init__()
        self.storage = storage
        self.worker: Stage1Worker | None = None
        self.analysis_running = False
        self._analysis_timer: QTimer | None = None
        self._analysis_start_ts: float | None = None
        self._analysis_message = "Starting analysis"
        self._analysis_step_text = "0/0"

        self.current_project: Project | None = None
        self.current_project_dir: Path | None = None
        self.current_run: Run | None = None
        self.current_run_dir: Path | None = None
        self.current_stage_id = STAGE_STATIC
        self.stage_ids = [stage_id for stage_id, _ in STAGES]

        self.findings: list[dict] = []
        self.log_paths: dict[str, Path] = {}
        self.artifact_paths: list[Path] = []
        self.tool_status_buttons: dict[str, QPushButton] = {}
        self._elide_labels: dict[QLabel, str] = {}
        self.project_search: QLineEdit | None = None
        self.project_list: QListWidget | None = None
        self.new_project_button: QPushButton | None = None
        self.open_project_folder_button: QPushButton | None = None
        self.project_card: QFrame | None = None
        self.project_name: QLabel | None = None
        self.project_id_label: QLabel | None = None
        self.project_path_label: QLabel | None = None
        self.project_apk_label: QLabel | None = None
        self.project_hash_label: QLabel | None = None
        self.project_size_label: QLabel | None = None
        self.project_imported_label: QLabel | None = None
        self.project_run_label: QLabel | None = None
        self.apk_version_combo: QComboBox | None = None
        self.tabs: QTabWidget | None = None
        self.stage_tabs: QTabWidget | None = None
        self.add_apk_button: QPushButton | None = None
        self.run_analysis_button: QPushButton | None = None
        self.open_report_button: QPushButton | None = None
        self.generate_report_button: QPushButton | None = None
        self.open_analysis_dir_button: QPushButton | None = None
        self.progress_label: QLabel | None = None
        self.progress_bar: QProgressBar | None = None
        self.status_badge: QLabel | None = None
        self.severity_filter: QComboBox | None = None
        self.category_filter: QComboBox | None = None
        self.findings_search: QLineEdit | None = None
        self.findings_table: QTableWidget | None = None
        self.log_combo: QComboBox | None = None
        self.log_search: QLineEdit | None = None
        self.log_autoscroll: QCheckBox | None = None
        self.log_view: QPlainTextEdit | None = None
        self.log_copy_button: QPushButton | None = None
        self.log_save_button: QPushButton | None = None
        self.log_open_button: QPushButton | None = None
        self.artifacts_open_button: QPushButton | None = None
        self.artifacts_reveal_button: QPushButton | None = None
        self.artifacts_table: QTableWidget | None = None

        self.mobsf_worker: MobSFSetupWorker | None = None
        self.mobsf_stop_worker: MobSFStopWorker | None = None
        self.mobsf_run_worker: Stage3Worker | None = None
        self.quark_run_worker: Stage3QuarkWorker | None = None
        self.apkid_run_worker: Stage3ApkidWorker | None = None
        self.apkleaks_run_worker: Stage3ApkleaksWorker | None = None
        self.mobsf_setup_in_progress = False
        self.mobsf_run_in_progress = False
        self.quark_run_in_progress = False
        self.apkid_run_in_progress = False
        self.apkleaks_run_in_progress = False
        self.mobsf_base_url = DEFAULT_MOBSF_URL
        self.mobsf_api_key: str | None = None
        self.mobsf_container_id: str | None = None
        self.mobsf_running = False
        self.mobsf_status_label: QLabel | None = None
        self.mobsf_scan_status_label: QLabel | None = None
        self.mobsf_summary_score: QLabel | None = None
        self.mobsf_summary_high: QLabel | None = None
        self.mobsf_summary_warning: QLabel | None = None
        self.mobsf_summary_trackers: QLabel | None = None
        self.mobsf_summary_updated: QLabel | None = None
        self.quark_status_label: QLabel | None = None
        self.quark_rules_label: QLabel | None = None
        self.quark_summary_total: QLabel | None = None
        self.quark_summary_matched: QLabel | None = None
        self.quark_summary_updated: QLabel | None = None
        self.quark_open_report_button: QPushButton | None = None
        self.quark_log_view: QPlainTextEdit | None = None
        self.quark_open_dir_button: QPushButton | None = None
        self.stage3_report_status: QLabel | None = None
        self.stage3_report_updated: QLabel | None = None
        self.mobsf_setup_button: QPushButton | None = None
        self.mobsf_stop_button: QPushButton | None = None
        self.mobsf_run_button: QPushButton | None = None
        self.mobsf_open_report_button: QPushButton | None = None
        self.mobsf_log_view: QPlainTextEdit | None = None
        self.mobsf_open_dir_button: QPushButton | None = None
        self.quark_run_button: QPushButton | None = None
        self.apkid_run_button: QPushButton | None = None
        self.stage3_mode_combo: QComboBox | None = None
        self.stage3_stack: QStackedWidget | None = None
        self.stage3_tabs: QTabWidget | None = None
        self.mobsf_progress_label: QLabel | None = None
        self.mobsf_progress_bar: QProgressBar | None = None
        self.quark_progress_label: QLabel | None = None
        self.quark_progress_bar: QProgressBar | None = None
        self.apkid_progress_label: QLabel | None = None
        self.apkid_progress_bar: QProgressBar | None = None
        self.apkid_status_label: QLabel | None = None
        self.apkid_summary_label: QLabel | None = None
        self.apkid_summary_updated: QLabel | None = None
        self.apkid_log_view: QPlainTextEdit | None = None
        self.apkid_open_dir_button: QPushButton | None = None
        self.apkid_report_button: QPushButton | None = None
        self.apkleaks_progress_label: QLabel | None = None
        self.apkleaks_progress_bar: QProgressBar | None = None
        self.apkleaks_status_label: QLabel | None = None
        self.apkleaks_run_button: QPushButton | None = None
        self.apkleaks_log_view: QPlainTextEdit | None = None
        self.apkleaks_summary_label: QLabel | None = None
        self.apkleaks_summary_updated: QLabel | None = None
        self.apkleaks_open_dir_button: QPushButton | None = None
        self.apkleaks_report_button: QPushButton | None = None
        self.stage3_metric_updated: QLabel | None = None
        self.stage3_metric_tools: QLabel | None = None
        self.stage3_metric_findings: QLabel | None = None
        self.stage3_metric_quark: QLabel | None = None
        self.stage3_metric_mobsf: QLabel | None = None
        self.stage3_metric_kinds: QLabel | None = None
        self.stage3_severity_filter: QComboBox | None = None
        self.stage3_category_filter: QComboBox | None = None
        self.stage3_findings_search: QLineEdit | None = None
        self.stage3_findings_table: QTableWidget | None = None
        self.stage3_log_combo: QComboBox | None = None
        self.stage3_log_search: QLineEdit | None = None
        self.stage3_log_autoscroll: QCheckBox | None = None
        self.stage3_log_view: QPlainTextEdit | None = None
        self.stage3_log_copy_button: QPushButton | None = None
        self.stage3_log_save_button: QPushButton | None = None
        self.stage3_log_open_button: QPushButton | None = None
        self.stage3_artifacts_open_button: QPushButton | None = None
        self.stage3_artifacts_reveal_button: QPushButton | None = None
        self.stage3_artifacts_table: QTableWidget | None = None
        self.stage3_findings: list[dict] = []
        self.stage3_log_paths: dict[str, Path] = {}
        self.stage3_run_dir: Path | None = None
        self.stage3_run_data: dict | None = None

        self.setWindowTitle("TAPKA — Tools for APK analysis")
        self.setMinimumSize(1100, 720)
        self.setObjectName("MainWindow")
        self._logo_path = Path(__file__).resolve().parent / "87288873-75ab-4871-bf62-f126ff451e6c.png"
        if self._logo_path.exists():
            self.setWindowIcon(QIcon(str(self._logo_path)))

        self._build_ui()
        self._load_mobsf_settings()
        self._apply_theme()
        self._setup_timers()
        self.refresh_projects()
        self._update_action_states()

    def _setup_timers(self) -> None:
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setInterval(1000)
        self._analysis_timer.timeout.connect(self._tick_analysis_timer)

    def closeEvent(self, event) -> None:  # pylint: disable=invalid-name
        try:
            stop_mobsf()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        super().closeEvent(event)

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)

        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(12, 12, 12, 12)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setChildrenCollapsible(False)
        root_layout.addWidget(splitter)

        self._build_sidebar(splitter)
        main_panel = self._build_main_panel()
        splitter.addWidget(main_panel)
        splitter.setCollapsible(0, False)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 820])

    def _build_sidebar(self, splitter: QSplitter) -> None:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(260)
        sidebar.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Expanding)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 16, 16, 16)
        sidebar_layout.setSpacing(12)

        logo_row = QHBoxLayout()
        logo_label = QLabel()
        logo_pixmap = QPixmap(str(self._logo_path))
        if not logo_pixmap.isNull():
            logo_label.setPixmap(
                logo_pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
            logo_label.setFixedSize(64, 64)
        logo_row.addWidget(logo_label)
        logo_row.addStretch()
        sidebar_layout.addLayout(logo_row)

        sidebar_header = QLabel("Projects")
        sidebar_header.setObjectName("sidebarTitle")
        sidebar_layout.addWidget(sidebar_header)

        self.project_search = QLineEdit()
        self.project_search.setPlaceholderText("Search projects")
        self.project_search.textChanged.connect(self._filter_projects)
        sidebar_layout.addWidget(self.project_search)

        self.project_list = QListWidget()
        self.project_list.itemSelectionChanged.connect(self._on_project_selected)
        self.project_list.itemDoubleClicked.connect(self._open_project_folder_from_item)
        self.project_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.project_list.customContextMenuRequested.connect(self._show_project_context_menu)
        sidebar_layout.addWidget(self.project_list, stretch=1)

        self.new_project_button = QPushButton("New Project")
        self.new_project_button.setObjectName("primaryButton")
        self.new_project_button.clicked.connect(self._create_project)
        sidebar_layout.addWidget(self.new_project_button)

        self.open_project_folder_button = QPushButton("Open Project Folder")
        self.open_project_folder_button.clicked.connect(self._open_project_folder)
        sidebar_layout.addWidget(self.open_project_folder_button)

        splitter.addWidget(sidebar)

    def _build_main_panel(self) -> QWidget:
        main_panel = QWidget()
        main_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_panel.setMinimumWidth(0)
        main_layout = QVBoxLayout(main_panel)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        self._build_header(main_layout)
        self._build_project_card(main_layout)
        self._build_stage_tabs(main_layout)
        return main_panel

    def _build_header(self, main_layout: QVBoxLayout) -> None:
        header_row = QHBoxLayout()
        header_title = QLabel("Current project")
        header_title.setObjectName("headerTitle")
        header_row.addWidget(header_title)
        header_row.addStretch()
        self.status_badge = QLabel("Idle")
        self.status_badge.setObjectName("statusBadge")
        header_row.addWidget(self.status_badge)
        main_layout.addLayout(header_row)

    def _build_project_card(self, main_layout: QVBoxLayout) -> None:
        self.project_card = QFrame()
        self.project_card.setObjectName("card")
        project_layout = QGridLayout(self.project_card)
        project_layout.setContentsMargins(16, 16, 16, 16)
        project_layout.setHorizontalSpacing(18)
        project_layout.setVerticalSpacing(8)

        self.project_name = QLabel("No project selected")
        self.project_name.setObjectName("projectName")
        self.project_name.setWordWrap(False)
        self.project_name.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.project_name.setMinimumWidth(0)
        self.project_id_label = QLabel("-")
        self.project_path_label = QLabel("-")
        self.project_apk_label = QLabel("-")
        self.project_hash_label = QLabel("-")
        self.project_size_label = QLabel("-")
        self.project_imported_label = QLabel("-")
        self.project_run_label = QLabel("-")
        self.apk_version_combo = QComboBox()
        self.apk_version_combo.currentIndexChanged.connect(self._on_version_changed)
        self.add_apk_button = QPushButton("Add APK")
        self.add_apk_button.clicked.connect(self._add_apk)

        for label in (
            self.project_id_label,
            self.project_path_label,
            self.project_apk_label,
            self.project_hash_label,
            self.project_size_label,
            self.project_imported_label,
            self.project_run_label,
        ):
            label.setWordWrap(False)
            label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            label.setMinimumWidth(0)

        project_layout.addWidget(QLabel("Name"), 0, 0)
        project_layout.addWidget(self.project_name, 0, 1)
        project_layout.addWidget(QLabel("Project ID"), 1, 0)
        project_layout.addWidget(self.project_id_label, 1, 1)
        project_layout.addWidget(QLabel("Project path"), 2, 0)
        project_layout.addWidget(self.project_path_label, 2, 1)
        project_layout.addWidget(QLabel("APK path"), 3, 0)
        project_layout.addWidget(self.project_apk_label, 3, 1)
        project_layout.addWidget(QLabel("APK version"), 4, 0)
        project_layout.addWidget(self.apk_version_combo, 4, 1)
        project_layout.addWidget(self.add_apk_button, 4, 2, 1, 2, Qt.AlignRight)
        project_layout.addWidget(QLabel("SHA256"), 0, 2)
        project_layout.addWidget(self.project_hash_label, 0, 3)
        project_layout.addWidget(QLabel("Size"), 1, 2)
        project_layout.addWidget(self.project_size_label, 1, 3)
        project_layout.addWidget(QLabel("Imported"), 2, 2)
        project_layout.addWidget(self.project_imported_label, 2, 3)
        project_layout.addWidget(QLabel("Last run"), 3, 2)
        project_layout.addWidget(self.project_run_label, 3, 3)

        project_layout.setColumnStretch(1, 1)
        project_layout.setColumnStretch(3, 1)
        project_layout.setColumnMinimumWidth(1, 0)
        project_layout.setColumnMinimumWidth(3, 0)
        main_layout.addWidget(self.project_card)

    def _build_stage_tabs(self, main_layout: QVBoxLayout) -> None:
        self.stage_tabs = QTabWidget()
        self.stage_tabs.setObjectName("stageTabs")
        self.stage_tabs.currentChanged.connect(self._on_stage_changed)

        self.stage_tabs.addTab(self._build_stage1_page(), STAGES[0][1])
        self.stage_tabs.addTab(
            self._build_stub_stage_page(
                "Dynamic analysis will be available in a future update.",
            ),
            STAGES[1][1],
        )
        self.stage_tabs.addTab(
            self._build_stage3_page(),
            STAGES[2][1],
        )
        self.stage_tabs.addTab(
            self._build_stub_stage_page(
                "Overall report will be available in a future update.",
            ),
            STAGES[3][1],
        )

        main_layout.addWidget(self.stage_tabs, stretch=1)

    def _build_stage1_page(self) -> QWidget:
        stage1_page = QWidget()
        stage1_layout = QVBoxLayout(stage1_page)
        stage1_layout.setContentsMargins(0, 0, 0, 0)
        stage1_layout.setSpacing(12)
        stage1_layout.addWidget(self._build_stage1_controls_card())
        stage1_layout.addWidget(self._build_checks_card())
        stage1_layout.addStretch(1)
        return stage1_page

    def _build_stage3_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        picker_row = QHBoxLayout()
        picker_label = QLabel("Analysis mode")
        picker_label.setObjectName("sectionTitle")
        picker_row.addWidget(picker_label)
        self.stage3_mode_combo = QComboBox()
        self.stage3_mode_combo.addItems(
            [
                "MobSF analysis",
                "Quark analysis",
                "APKiD analysis",
                "APKLeaks analysis",
            ]
        )
        self.stage3_mode_combo.currentIndexChanged.connect(self._on_stage3_mode_changed)
        picker_row.addWidget(self.stage3_mode_combo, stretch=1)
        layout.addLayout(picker_row)
        self.stage3_stack = QStackedWidget()
        self.stage3_stack.addWidget(self._build_stage3_mobsf_page())
        self.stage3_stack.addWidget(self._build_stage3_quark_page())
        self.stage3_stack.addWidget(self._build_stage3_apkid_page())
        self.stage3_stack.addWidget(self._build_stage3_apkleaks_page())
        if self.stage3_mode_combo:
            self.stage3_stack.setCurrentIndex(self.stage3_mode_combo.currentIndex())
        layout.addWidget(self.stage3_stack)
        return page

    def _build_stage3_mobsf_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(self._build_mobsf_setup_card())
        return page

    def _build_stage3_quark_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(self._build_quark_card())
        return page

    def _build_stage3_apkid_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(8)

        header = QLabel("APKiD analysis")
        header.setObjectName("sectionTitle")
        card_layout.addWidget(header)

        hint = QLabel("Run APKiD signatures on the selected APK and collect detector matches.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        card_layout.addWidget(hint)

        button_row = QHBoxLayout()
        self.apkid_run_button = QPushButton("Run APKiD")
        self.apkid_run_button.setObjectName("primaryButton")
        self.apkid_run_button.clicked.connect(self._run_apkid_analysis)
        button_row.addWidget(self.apkid_run_button)

        self.apkid_report_button = QPushButton("Open report")
        self.apkid_report_button.clicked.connect(self._open_apkid_report_stub)
        button_row.addWidget(self.apkid_report_button)

        button_row.addStretch()
        card_layout.addLayout(button_row)

        status_form = QFormLayout()
        status_form.setHorizontalSpacing(16)
        status_form.setVerticalSpacing(6)
        self.apkid_status_label = QLabel("Ready")
        self.apkid_status_label.setObjectName("muted")
        status_form.addRow("Status:", self.apkid_status_label)
        self.apkid_summary_label = QLabel("-")
        self.apkid_summary_label.setObjectName("muted")
        status_form.addRow("Matches:", self.apkid_summary_label)
        self.apkid_summary_updated = QLabel("-")
        self.apkid_summary_updated.setObjectName("muted")
        status_form.addRow("Last scan:", self.apkid_summary_updated)
        card_layout.addLayout(status_form)

        progress_row = QHBoxLayout()
        self.apkid_progress_label = QLabel("Ready")
        self.apkid_progress_label.setObjectName("muted")
        progress_row.addWidget(self.apkid_progress_label, stretch=1)
        self.apkid_progress_bar = QProgressBar()
        self.apkid_progress_bar.setMinimum(0)
        self.apkid_progress_bar.setMaximum(1)
        self.apkid_progress_bar.setValue(0)
        progress_row.addWidget(self.apkid_progress_bar, stretch=2)
        card_layout.addLayout(progress_row)

        log_label = QLabel("Output log")
        log_label.setObjectName("sectionTitle")
        card_layout.addWidget(log_label)

        self.apkid_log_view = QPlainTextEdit()
        self.apkid_log_view.setReadOnly(True)
        self.apkid_log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.apkid_log_view.setMaximumBlockCount(200)
        self.apkid_log_view.setPlaceholderText("APKiD logs will appear here.")
        card_layout.addWidget(self.apkid_log_view)

        self.apkid_open_dir_button = QPushButton("Open analysis directory")
        self.apkid_open_dir_button.clicked.connect(
            lambda: self._open_stage3_tool_dir("apkid", self._append_apkid_log)
        )
        card_layout.addWidget(self.apkid_open_dir_button)

        layout.addWidget(card)
        return page

    def _build_stage3_apkleaks_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(8)

        header = QLabel("APKLeaks analysis")
        header.setObjectName("sectionTitle")
        card_layout.addWidget(header)

        hint = QLabel("Run APKLeaks patterns on the selected APK and capture extracted entries.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        card_layout.addWidget(hint)

        button_row = QHBoxLayout()
        self.apkleaks_run_button = QPushButton("Run APKLeaks")
        self.apkleaks_run_button.setObjectName("primaryButton")
        self.apkleaks_run_button.clicked.connect(self._run_apkleaks_analysis)
        button_row.addWidget(self.apkleaks_run_button)

        self.apkleaks_report_button = QPushButton("Open report")
        self.apkleaks_report_button.clicked.connect(self._open_apkleaks_report_stub)
        button_row.addWidget(self.apkleaks_report_button)

        button_row.addStretch()
        card_layout.addLayout(button_row)

        summary_form = QFormLayout()
        summary_form.setHorizontalSpacing(16)
        summary_form.setVerticalSpacing(6)
        self.apkleaks_status_label = QLabel("Ready")
        self.apkleaks_status_label.setObjectName("muted")
        summary_form.addRow("Status:", self.apkleaks_status_label)
        self.apkleaks_summary_label = QLabel("-")
        self.apkleaks_summary_label.setObjectName("muted")
        summary_form.addRow("Entries:", self.apkleaks_summary_label)
        self.apkleaks_summary_updated = QLabel("-")
        self.apkleaks_summary_updated.setObjectName("muted")
        summary_form.addRow("Last scan:", self.apkleaks_summary_updated)
        card_layout.addLayout(summary_form)

        progress_row = QHBoxLayout()
        self.apkleaks_progress_label = QLabel("Ready")
        self.apkleaks_progress_label.setObjectName("muted")
        progress_row.addWidget(self.apkleaks_progress_label, stretch=1)
        self.apkleaks_progress_bar = QProgressBar()
        self.apkleaks_progress_bar.setMinimum(0)
        self.apkleaks_progress_bar.setMaximum(1)
        self.apkleaks_progress_bar.setValue(0)
        progress_row.addWidget(self.apkleaks_progress_bar, stretch=2)
        card_layout.addLayout(progress_row)

        log_label = QLabel("Output log")
        log_label.setObjectName("sectionTitle")
        card_layout.addWidget(log_label)

        self.apkleaks_log_view = QPlainTextEdit()
        self.apkleaks_log_view.setReadOnly(True)
        self.apkleaks_log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.apkleaks_log_view.setMaximumBlockCount(200)
        self.apkleaks_log_view.setPlaceholderText("APKLeaks logs will appear here.")
        card_layout.addWidget(self.apkleaks_log_view)

        self.apkleaks_open_dir_button = QPushButton("Open analysis directory")
        self.apkleaks_open_dir_button.clicked.connect(
            lambda: self._open_stage3_tool_dir("apkleaks", self._append_apkleaks_log)
        )
        card_layout.addWidget(self.apkleaks_open_dir_button)

        layout.addWidget(card)
        return page

    def _build_stage3_stub_card(self, title: str, message: str) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        header = QLabel(title)
        header.setObjectName("sectionTitle")
        layout.addWidget(header)
        hint = QLabel(message)
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return card

    def _build_mobsf_setup_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("MobSF analysis")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)

        hint = QLabel("Start MobSF in Docker and run scans against the selected APK.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        button_row = QHBoxLayout()
        self.mobsf_setup_button = QPushButton("Start MobSF")
        self.mobsf_setup_button.setObjectName("primaryButton")
        self.mobsf_setup_button.clicked.connect(self._start_mobsf_setup)
        button_row.addWidget(self.mobsf_setup_button)

        self.mobsf_stop_button = QPushButton("Stop MobSF")
        self.mobsf_stop_button.clicked.connect(self._stop_mobsf)
        button_row.addWidget(self.mobsf_stop_button)

        self.mobsf_run_button = QPushButton("Run MobSF")
        self.mobsf_run_button.clicked.connect(self._run_mobsf_analysis)
        button_row.addWidget(self.mobsf_run_button)

        self.mobsf_open_report_button = QPushButton("Open MobSF report")
        self.mobsf_open_report_button.clicked.connect(self._open_stage3_report)
        button_row.addWidget(self.mobsf_open_report_button)

        button_row.addStretch()
        layout.addLayout(button_row)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(6)

        self.mobsf_status_label = QLabel("Not configured")
        self.mobsf_status_label.setObjectName("muted")
        form.addRow("Status:", self.mobsf_status_label)

        self.mobsf_scan_status_label = QLabel("Idle")
        self.mobsf_scan_status_label.setObjectName("muted")
        form.addRow("Scan status:", self.mobsf_scan_status_label)

        layout.addLayout(form)

        summary_header = QLabel("Scan summary")
        summary_header.setObjectName("sectionTitle")
        layout.addWidget(summary_header)

        summary_form = QFormLayout()
        summary_form.setHorizontalSpacing(16)
        summary_form.setVerticalSpacing(6)

        self.mobsf_summary_score = QLabel("-")
        self.mobsf_summary_score.setObjectName("muted")
        summary_form.addRow("Security score:", self.mobsf_summary_score)

        self.mobsf_summary_high = QLabel("-")
        self.mobsf_summary_high.setObjectName("muted")
        summary_form.addRow("High findings:", self.mobsf_summary_high)

        self.mobsf_summary_warning = QLabel("-")
        self.mobsf_summary_warning.setObjectName("muted")
        summary_form.addRow("Warnings:", self.mobsf_summary_warning)

        self.mobsf_summary_trackers = QLabel("-")
        self.mobsf_summary_trackers.setObjectName("muted")
        summary_form.addRow("Trackers:", self.mobsf_summary_trackers)

        self.mobsf_summary_updated = QLabel("-")
        self.mobsf_summary_updated.setObjectName("muted")
        summary_form.addRow("Last scan:", self.mobsf_summary_updated)

        layout.addLayout(summary_form)

        progress_row = QHBoxLayout()
        self.mobsf_progress_label = QLabel("Ready")
        self.mobsf_progress_label.setObjectName("muted")
        progress_row.addWidget(self.mobsf_progress_label, stretch=1)
        self.mobsf_progress_bar = QProgressBar()
        self.mobsf_progress_bar.setMinimum(0)
        self.mobsf_progress_bar.setMaximum(1)
        self.mobsf_progress_bar.setValue(0)
        progress_row.addWidget(self.mobsf_progress_bar, stretch=2)
        layout.addLayout(progress_row)

        log_label = QLabel("Output log")
        log_label.setObjectName("sectionTitle")
        layout.addWidget(log_label)

        self.mobsf_log_view = QPlainTextEdit()
        self.mobsf_log_view.setReadOnly(True)
        self.mobsf_log_view.setMaximumBlockCount(200)
        self.mobsf_log_view.setPlaceholderText("MobSF setup logs will appear here.")
        layout.addWidget(self.mobsf_log_view)

        self.mobsf_open_dir_button = QPushButton("Open analysis directory")
        self.mobsf_open_dir_button.clicked.connect(
            lambda: self._open_stage3_tool_dir("mobsf", self._append_mobsf_log)
        )
        layout.addWidget(self.mobsf_open_dir_button)
        return card

    def _build_quark_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("Quark analysis")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)

        hint = QLabel("Quark rules are loaded from .tapka/quark-rules and run during Stage3 scans.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        button_row = QHBoxLayout()
        self.quark_run_button = QPushButton("Run Quark")
        self.quark_run_button.setObjectName("primaryButton")
        self.quark_run_button.clicked.connect(self._run_quark_analysis)
        button_row.addWidget(self.quark_run_button)

        self.quark_open_report_button = QPushButton("Open report")
        self.quark_open_report_button.clicked.connect(self._open_stage3_report)
        button_row.addWidget(self.quark_open_report_button)

        button_row.addStretch()
        layout.addLayout(button_row)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(6)

        self.quark_status_label = QLabel("Not configured")
        self.quark_status_label.setObjectName("muted")
        form.addRow("Status:", self.quark_status_label)

        self.quark_rules_label = QLabel("-")
        self.quark_rules_label.setObjectName("muted")
        form.addRow("Rules:", self.quark_rules_label)

        self.quark_summary_total = QLabel("-")
        self.quark_summary_total.setObjectName("muted")
        form.addRow("Rules total:", self.quark_summary_total)

        self.quark_summary_matched = QLabel("-")
        self.quark_summary_matched.setObjectName("muted")
        form.addRow("Rules matched:", self.quark_summary_matched)

        self.quark_summary_updated = QLabel("-")
        self.quark_summary_updated.setObjectName("muted")
        form.addRow("Last scan:", self.quark_summary_updated)

        layout.addLayout(form)

        progress_row = QHBoxLayout()
        self.quark_progress_label = QLabel("Ready")
        self.quark_progress_label.setObjectName("muted")
        progress_row.addWidget(self.quark_progress_label, stretch=1)
        self.quark_progress_bar = QProgressBar()
        self.quark_progress_bar.setMinimum(0)
        self.quark_progress_bar.setMaximum(1)
        self.quark_progress_bar.setValue(0)
        progress_row.addWidget(self.quark_progress_bar, stretch=2)
        layout.addLayout(progress_row)

        log_label = QLabel("Output log")
        log_label.setObjectName("sectionTitle")
        layout.addWidget(log_label)

        self.quark_log_view = QPlainTextEdit()
        self.quark_log_view.setReadOnly(True)
        self.quark_log_view.setMaximumBlockCount(200)
        self.quark_log_view.setPlaceholderText("Quark logs will appear here.")
        layout.addWidget(self.quark_log_view)

        self.quark_open_dir_button = QPushButton("Open analysis directory")
        self.quark_open_dir_button.clicked.connect(
            lambda: self._open_stage3_tool_dir("quark", self._append_quark_log)
        )
        layout.addWidget(self.quark_open_dir_button)
        return card

    def _build_stage3_report_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("Stage3 report")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(6)

        self.stage3_report_status = QLabel("-")
        self.stage3_report_status.setObjectName("muted")
        form.addRow("Status:", self.stage3_report_status)

        self.stage3_report_updated = QLabel("-")
        self.stage3_report_updated.setObjectName("muted")
        form.addRow("Finished:", self.stage3_report_updated)

        layout.addLayout(form)

        button_row = QHBoxLayout()
        self.mobsf_open_report_button = QPushButton("Open Stage3 report")
        self.mobsf_open_report_button.clicked.connect(self._open_stage3_report)
        button_row.addWidget(self.mobsf_open_report_button)
        button_row.addStretch()
        layout.addLayout(button_row)
        return card

    def _build_stub_stage_page(self, hint_text: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        hint = QLabel(hint_text)
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        open_button = QPushButton("Open report")
        open_button.clicked.connect(self._open_report)
        layout.addWidget(open_button)
        layout.addStretch()
        return page

    def _build_stage1_controls_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        header = QLabel("Static analysis")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)

        hint = QLabel("Run local static tools and generate reports for the selected APK.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        self.run_analysis_button = QPushButton("Run analysis")
        self.run_analysis_button.setObjectName("primaryButton")
        self.run_analysis_button.clicked.connect(self._run_analysis)
        button_row.addWidget(self.run_analysis_button)

        self.open_report_button = QPushButton("Open report")
        self.open_report_button.clicked.connect(self._open_report)
        button_row.addWidget(self.open_report_button)

        self.generate_report_button = QPushButton("Generate report")
        self.generate_report_button.clicked.connect(self._generate_report)
        button_row.addWidget(self.generate_report_button)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        status_row = QHBoxLayout()
        status_title = QLabel("Status:")
        status_title.setObjectName("sectionTitle")
        status_row.addWidget(status_title)
        self.progress_label = QLabel("Ready")
        self.progress_label.setObjectName("muted")
        status_row.addWidget(self.progress_label, stretch=1)
        layout.addLayout(status_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.open_analysis_dir_button = QPushButton("Open analysis directory")
        self.open_analysis_dir_button.clicked.connect(self._open_stage1_run_dir)
        layout.addWidget(self.open_analysis_dir_button)
        return card

    def _build_stage3_actions_card(self) -> QFrame:
        actions_card = QFrame()
        actions_card.setObjectName("card")
        actions_layout = QHBoxLayout(actions_card)
        actions_layout.setContentsMargins(16, 12, 16, 12)
        actions_layout.setSpacing(10)

        self.stage3_run_button = QPushButton("Run analysis")
        self.stage3_run_button.setObjectName("primaryButton")
        self.stage3_run_button.clicked.connect(self._run_stage3_analysis)
        actions_layout.addWidget(self.stage3_run_button)

        self.stage3_open_report_button = QPushButton("Open report")
        self.stage3_open_report_button.clicked.connect(self._open_stage3_report)
        actions_layout.addWidget(self.stage3_open_report_button)

        self.stage3_generate_report_button = QPushButton("Generate report")
        self.stage3_generate_report_button.clicked.connect(self._generate_stage3_report)
        actions_layout.addWidget(self.stage3_generate_report_button)

        actions_layout.addStretch()
        return actions_card

    def _build_stage3_progress_card(self) -> QFrame:
        progress_card = QFrame()
        progress_card.setObjectName("card")
        progress_layout = QHBoxLayout(progress_card)
        progress_layout.setContentsMargins(16, 10, 16, 10)

        self.stage3_progress_label = QLabel("Ready")
        self.stage3_progress_label.setObjectName("muted")
        progress_layout.addWidget(self.stage3_progress_label, stretch=1)

        self.stage3_progress_bar = QProgressBar()
        self.stage3_progress_bar.setMinimum(0)
        self.stage3_progress_bar.setMaximum(1)
        self.stage3_progress_bar.setValue(0)
        progress_layout.addWidget(self.stage3_progress_bar, stretch=2)
        return progress_card

    def _build_stage3_overview_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        metrics_grid = QGridLayout()
        metrics_grid.setHorizontalSpacing(12)
        metrics_grid.setVerticalSpacing(12)

        self.stage3_metric_updated = self._add_metric_card(metrics_grid, 0, 0, "Last analysis")
        self.stage3_metric_tools = self._add_metric_card(metrics_grid, 0, 1, "Tools executed")
        self.stage3_metric_findings = self._add_metric_card(metrics_grid, 0, 2, "Findings total")
        self.stage3_metric_quark = self._add_metric_card(metrics_grid, 1, 0, "Quark status")
        self.stage3_metric_mobsf = self._add_metric_card(metrics_grid, 1, 1, "MobSF status")
        self.stage3_metric_kinds = self._add_metric_card(metrics_grid, 1, 2, "Kinds breakdown")

        layout.addLayout(metrics_grid)
        layout.addStretch()
        if self.stage3_tabs:
            self.stage3_tabs.addTab(tab, "Overview")

    def _build_stage3_findings_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        self.stage3_severity_filter = QComboBox()
        self.stage3_severity_filter.addItems(["All"])
        self.stage3_severity_filter.currentIndexChanged.connect(self._apply_stage3_findings_filters)
        filter_row.addWidget(QLabel("Severity"))
        filter_row.addWidget(self.stage3_severity_filter)

        self.stage3_category_filter = QComboBox()
        self.stage3_category_filter.addItems(["All"])
        self.stage3_category_filter.currentIndexChanged.connect(self._apply_stage3_findings_filters)
        filter_row.addWidget(QLabel("Category"))
        filter_row.addWidget(self.stage3_category_filter)

        self.stage3_findings_search = QLineEdit()
        self.stage3_findings_search.setPlaceholderText("Search findings")
        self.stage3_findings_search.textChanged.connect(self._apply_stage3_findings_filters)
        filter_row.addWidget(self.stage3_findings_search, stretch=1)

        layout.addLayout(filter_row)

        self.stage3_findings_table = QTableWidget(0, 5)
        self.stage3_findings_table.setHorizontalHeaderLabels(
            ["Severity", "Category", "Title", "Location", "Evidence"]
        )
        self.stage3_findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stage3_findings_table.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.stage3_findings_table.setMinimumWidth(0)
        self.stage3_findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.stage3_findings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.stage3_findings_table.setAlternatingRowColors(True)
        self.stage3_findings_table.itemDoubleClicked.connect(self._open_stage3_finding_source)
        layout.addWidget(self.stage3_findings_table)

        if self.stage3_tabs:
            self.stage3_tabs.addTab(tab, "Findings")

    def _build_stage3_logs_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        self.stage3_log_combo = QComboBox()
        self.stage3_log_combo.currentIndexChanged.connect(self._render_stage3_log_view)
        top_row.addWidget(QLabel("Log"))
        top_row.addWidget(self.stage3_log_combo)

        self.stage3_log_search = QLineEdit()
        self.stage3_log_search.setPlaceholderText("Filter logs")
        self.stage3_log_search.textChanged.connect(self._render_stage3_log_view)
        top_row.addWidget(self.stage3_log_search, stretch=1)

        self.stage3_log_autoscroll = QCheckBox("Auto-scroll")
        self.stage3_log_autoscroll.setChecked(True)
        top_row.addWidget(self.stage3_log_autoscroll)
        layout.addLayout(top_row)

        self.stage3_log_view = QPlainTextEdit()
        self.stage3_log_view.setReadOnly(True)
        self.stage3_log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.stage3_log_view.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.stage3_log_view.setMinimumWidth(0)
        layout.addWidget(self.stage3_log_view, stretch=1)

        action_row = QHBoxLayout()
        self.stage3_log_copy_button = QPushButton("Copy")
        self.stage3_log_copy_button.clicked.connect(self._copy_stage3_log)
        action_row.addWidget(self.stage3_log_copy_button)

        self.stage3_log_save_button = QPushButton("Save")
        self.stage3_log_save_button.clicked.connect(self._save_stage3_log)
        action_row.addWidget(self.stage3_log_save_button)

        self.stage3_log_open_button = QPushButton("Open log file")
        self.stage3_log_open_button.clicked.connect(self._open_stage3_log_file)
        action_row.addWidget(self.stage3_log_open_button)

        action_row.addStretch()
        layout.addLayout(action_row)

        if self.stage3_tabs:
            self.stage3_tabs.addTab(tab, "Logs")

    def _build_stage3_artifacts_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        action_row = QHBoxLayout()
        self.stage3_artifacts_open_button = QPushButton("Open")
        self.stage3_artifacts_open_button.clicked.connect(self._open_stage3_artifact)
        action_row.addWidget(self.stage3_artifacts_open_button)

        self.stage3_artifacts_reveal_button = QPushButton("Reveal in folder")
        self.stage3_artifacts_reveal_button.clicked.connect(self._reveal_stage3_artifact)
        action_row.addWidget(self.stage3_artifacts_reveal_button)

        action_row.addStretch()
        layout.addLayout(action_row)

        self.stage3_artifacts_table = QTableWidget(0, 3)
        self.stage3_artifacts_table.setHorizontalHeaderLabels(["Name", "Path", "Size"])
        self.stage3_artifacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stage3_artifacts_table.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.stage3_artifacts_table.setMinimumWidth(0)
        self.stage3_artifacts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.stage3_artifacts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.stage3_artifacts_table.setAlternatingRowColors(True)
        self.stage3_artifacts_table.itemDoubleClicked.connect(self._open_stage3_artifact)
        layout.addWidget(self.stage3_artifacts_table)

        if self.stage3_tabs:
            self.stage3_tabs.addTab(tab, "Artifacts")

    def _build_checks_card(self) -> QFrame:
        checks_card = QFrame()
        checks_card.setObjectName("card")
        checks_layout = QVBoxLayout(checks_card)
        checks_layout.setContentsMargins(16, 12, 16, 12)
        checks_layout.setSpacing(8)

        checks_header = QLabel("Checks")
        checks_header.setObjectName("sectionTitle")
        checks_layout.addWidget(checks_header)

        status_layout = QFormLayout()
        status_layout.setHorizontalSpacing(16)
        status_layout.setVerticalSpacing(6)
        for tool, label in self.TOOL_STATUS_DEFS:
            status_button = QPushButton("Not run")
            status_button.setObjectName("toolStatus")
            status_button.setProperty("status", "pending")
            status_button.setFlat(True)
            status_button.setCursor(Qt.ArrowCursor)
            status_button.clicked.connect(lambda _checked=False, tool=tool: self._open_tool_stderr(tool))
            status_layout.addRow(f"{label}:", status_button)
            self.tool_status_buttons[tool] = status_button
        checks_layout.addLayout(status_layout)
        return checks_card

    def _build_stage1_log_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("Output log")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(200)
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_view.setPlaceholderText("Stage1 logs will appear here.")
        layout.addWidget(self.log_view)
        return card

    def _add_metric_card(self, grid: QGridLayout, row: int, col: int, title: str) -> QLabel:
        card = QFrame()
        card.setObjectName("metricCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 14, 14, 14)
        card_layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setObjectName("metricTitle")
        value_label = QLabel("--")
        value_label.setObjectName("metricValue")

        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)

        grid.addWidget(card, row, col)
        return value_label

    def _build_findings_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", *self.SEVERITY_ORDER])
        self.severity_filter.currentIndexChanged.connect(self._apply_findings_filters)
        filter_row.addWidget(QLabel("Severity"))
        filter_row.addWidget(self.severity_filter)

        self.category_filter = QComboBox()
        self.category_filter.addItems(["All"])
        self.category_filter.currentIndexChanged.connect(self._apply_findings_filters)
        filter_row.addWidget(QLabel("Category"))
        filter_row.addWidget(self.category_filter)

        self.findings_search = QLineEdit()
        self.findings_search.setPlaceholderText("Search findings")
        self.findings_search.textChanged.connect(self._apply_findings_filters)
        filter_row.addWidget(self.findings_search, stretch=1)

        layout.addLayout(filter_row)

        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(
            ["Severity", "Category", "Title", "Location", "Evidence"]
        )
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.findings_table.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.findings_table.setMinimumWidth(0)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.findings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.itemDoubleClicked.connect(self._open_finding_source)
        layout.addWidget(self.findings_table)

        self.tabs.addTab(tab, "Findings")

    def _build_logs_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        self.log_combo = QComboBox()
        self.log_combo.currentIndexChanged.connect(self._render_log_view)
        top_row.addWidget(QLabel("Log"))
        top_row.addWidget(self.log_combo)

        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Filter logs")
        self.log_search.textChanged.connect(self._render_log_view)
        top_row.addWidget(self.log_search, stretch=1)

        self.log_autoscroll = QCheckBox("Auto-scroll")
        self.log_autoscroll.setChecked(True)
        top_row.addWidget(self.log_autoscroll)
        layout.addLayout(top_row)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_view.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.log_view.setMinimumWidth(0)
        layout.addWidget(self.log_view, stretch=1)

        action_row = QHBoxLayout()
        self.log_copy_button = QPushButton("Copy")
        self.log_copy_button.clicked.connect(self._copy_log)
        action_row.addWidget(self.log_copy_button)

        self.log_save_button = QPushButton("Save")
        self.log_save_button.clicked.connect(self._save_log)
        action_row.addWidget(self.log_save_button)

        self.log_open_button = QPushButton("Open log file")
        self.log_open_button.clicked.connect(self._open_log_file)
        action_row.addWidget(self.log_open_button)

        action_row.addStretch()
        layout.addLayout(action_row)

        self.tabs.addTab(tab, "Logs")

    def _build_artifacts_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        action_row = QHBoxLayout()
        self.artifacts_open_button = QPushButton("Open")
        self.artifacts_open_button.clicked.connect(self._open_artifact)
        action_row.addWidget(self.artifacts_open_button)

        self.artifacts_reveal_button = QPushButton("Reveal in folder")
        self.artifacts_reveal_button.clicked.connect(self._reveal_artifact)
        action_row.addWidget(self.artifacts_reveal_button)

        action_row.addStretch()
        layout.addLayout(action_row)

        self.artifacts_table = QTableWidget(0, 3)
        self.artifacts_table.setHorizontalHeaderLabels(["Name", "Path", "Size"])
        self.artifacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.artifacts_table.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.artifacts_table.setMinimumWidth(0)
        self.artifacts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.artifacts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.artifacts_table.setAlternatingRowColors(True)
        self.artifacts_table.itemDoubleClicked.connect(self._open_artifact)
        layout.addWidget(self.artifacts_table)

        self.tabs.addTab(tab, "Artifacts")

    def _apply_theme(self) -> None:
        self.setStyleSheet(get_style())

    def _load_mobsf_settings(self) -> None:
        settings = load_settings()
        mobsf = settings.get("mobsf", {})
        self.mobsf_base_url = mobsf.get("url", DEFAULT_MOBSF_URL)
        self.mobsf_api_key = mobsf.get("api_key")
        self.mobsf_container_id = mobsf.get("container_id")
        self.mobsf_running = False
        self._update_mobsf_labels()

    def _save_mobsf_settings(self) -> None:
        settings = load_settings()
        mobsf = settings.get("mobsf", {})
        mobsf["url"] = self.mobsf_base_url
        if self.mobsf_api_key:
            mobsf["api_key"] = self.mobsf_api_key
        if self.mobsf_container_id:
            mobsf["container_id"] = self.mobsf_container_id
        settings["mobsf"] = mobsf
        save_settings(settings)

    def _update_mobsf_labels(self) -> None:
        if self.mobsf_status_label:
            if self.mobsf_running:
                status = "Running"
            else:
                status = "Ready" if self.mobsf_api_key else "Not configured"
            self.mobsf_status_label.setText(status)

    def _set_mobsf_status(self, text: str) -> None:
        if self.mobsf_status_label:
            self.mobsf_status_label.setText(text)

    def _set_mobsf_scan_status(self, text: str) -> None:
        if self.mobsf_scan_status_label:
            self.mobsf_scan_status_label.setText(text)

    def _normalize_mobsf_url(self) -> None:
        self.mobsf_base_url = normalize_base_url(self.mobsf_base_url)

    def _append_mobsf_log(self, message: str) -> None:
        if not self.mobsf_log_view:
            return
        self.mobsf_log_view.appendPlainText(message)
        self.mobsf_log_view.verticalScrollBar().setValue(
            self.mobsf_log_view.verticalScrollBar().maximum()
        )

    def _append_quark_log(self, message: str) -> None:
        if not self.quark_log_view:
            return
        self.quark_log_view.appendPlainText(message)
        self.quark_log_view.verticalScrollBar().setValue(
            self.quark_log_view.verticalScrollBar().maximum()
        )
        percent = None
        match = re.search(r"(\d{1,3})%", message)
        if match:
            try:
                percent = int(match.group(1))
            except ValueError:
                percent = None
        if percent is not None:
            if percent < 0:
                percent = 0
            if percent > 100:
                percent = 100
            if self.quark_progress_bar:
                self.quark_progress_bar.setMaximum(100)
                self.quark_progress_bar.setValue(percent)
            if self.quark_progress_label:
                self.quark_progress_label.setText(f"Progress {percent}%")
        elif self.quark_progress_label:
            self.quark_progress_label.setText(message)

    def _handle_mobsf_progress(self, message: str) -> None:
        prefix = "MOBSF_SCAN_STATUS:"
        if message.startswith(prefix):
            status = message[len(prefix):].strip() or "-"
            self._set_mobsf_scan_status(status)
            self._append_mobsf_log(f"Scan status: {status}")
            return
        self._append_mobsf_log(message)
        if self.mobsf_progress_label:
            self.mobsf_progress_label.setText(message)

    def _append_apkid_log(self, message: str) -> None:
        if self.apkid_progress_label:
            self.apkid_progress_label.setText(message)
        if self.apkid_log_view:
            self.apkid_log_view.appendPlainText(message)

    def _append_apkleaks_log(self, message: str) -> None:
        if self.apkleaks_status_label and self.apkleaks_run_in_progress:
            self.apkleaks_status_label.setText("Running")
        if self.apkleaks_progress_label:
            self.apkleaks_progress_label.setText(message)
        if self.apkleaks_log_view:
            self.apkleaks_log_view.appendPlainText(message)
            self.apkleaks_log_view.verticalScrollBar().setValue(
                self.apkleaks_log_view.verticalScrollBar().maximum()
            )

    def _start_mobsf_setup(self) -> None:
        if self.mobsf_setup_in_progress:
            return
        self._normalize_mobsf_url()
        self.mobsf_setup_in_progress = True
        if self.mobsf_log_view:
            self.mobsf_log_view.clear()
        self._set_mobsf_status("Starting...")
        self._append_mobsf_log("Preparing MobSF setup...")
        self._update_action_states()

        self.mobsf_worker = MobSFSetupWorker(self.mobsf_base_url, self.mobsf_api_key)
        self.mobsf_worker.progress.connect(self._append_mobsf_log)
        self.mobsf_worker.finished.connect(self._on_mobsf_setup_finished)
        self.mobsf_worker.failed.connect(self._on_mobsf_setup_failed)
        self.mobsf_worker.start()

    def _on_mobsf_setup_finished(self, result) -> None:
        self.mobsf_setup_in_progress = False
        self.mobsf_base_url = result.base_url
        self.mobsf_api_key = result.api_key
        self.mobsf_container_id = result.container_id
        self.mobsf_running = True
        self._save_mobsf_settings()
        self._update_mobsf_labels()
        self._append_mobsf_log("MobSF is ready.")
        self._set_mobsf_scan_status("Idle")
        self._update_action_states()

    def _on_mobsf_setup_failed(self, message: str) -> None:
        self.mobsf_setup_in_progress = False
        self.mobsf_running = False
        self._set_mobsf_status("Failed")
        self._set_mobsf_scan_status("Idle")
        self._append_mobsf_log("MobSF setup failed.")
        self._update_action_states()
        QMessageBox.warning(self, "MobSF setup failed", message)

    def _stop_mobsf(self) -> None:
        if self.mobsf_setup_in_progress:
            return
        self.mobsf_setup_in_progress = True
        self._set_mobsf_status("Stopping...")
        self._append_mobsf_log("Stopping MobSF...")
        self._update_action_states()

        self.mobsf_stop_worker = MobSFStopWorker()
        self.mobsf_stop_worker.progress.connect(self._append_mobsf_log)
        self.mobsf_stop_worker.finished.connect(self._on_mobsf_stop_finished)
        self.mobsf_stop_worker.failed.connect(self._on_mobsf_stop_failed)
        self.mobsf_stop_worker.start()

    def _on_mobsf_stop_finished(self, stopped: bool) -> None:
        self.mobsf_setup_in_progress = False
        self.mobsf_running = False
        self._update_mobsf_labels()
        self._set_mobsf_scan_status("Idle")
        if stopped:
            self._append_mobsf_log("MobSF stopped.")
        else:
            self._append_mobsf_log("MobSF container was not running.")
        self._update_action_states()

    def _on_mobsf_stop_failed(self, message: str) -> None:
        self.mobsf_setup_in_progress = False
        self._set_mobsf_status("Stop failed")
        self._append_mobsf_log("MobSF stop failed.")
        self._update_action_states()
        QMessageBox.warning(self, "MobSF stop failed", message)

    def _run_stage3_analysis(self) -> None:
        if (
            self.mobsf_run_in_progress
            or self.quark_run_in_progress
            or self.apkid_run_in_progress
            or self.apkleaks_run_in_progress
        ):
            return
        if not self.current_project or not self.current_project.apk_meta:
            QMessageBox.warning(self, "Stage3", "Select a project with an APK first.")
            return
        selection = ""
        if self.stage3_mode_combo:
            selection = self.stage3_mode_combo.currentText()
        else:
            selection, ok = QInputDialog.getItem(
                self,
                "Stage3 analysis",
                "Select analysis",
                ["MobSF analysis", "Quark analysis"],
                0,
                False,
            )
            if not ok:
                return
        if selection.startswith("MobSF"):
            self._run_mobsf_analysis()
        elif selection.startswith("Quark"):
            self._run_quark_analysis()
        elif selection.startswith("APKiD"):
            self._run_apkid_analysis()
        elif selection.startswith("APKLeaks"):
            self._run_apkleaks_analysis()
        else:
            QMessageBox.information(self, "Stage3", "Selected analysis is not implemented yet.")

    def _run_mobsf_analysis(self) -> None:
        if self.mobsf_run_in_progress:
            return
        if not self.current_project or not self.current_project.apk_meta:
            QMessageBox.warning(self, "MobSF", "Select a project with an APK first.")
            return
        if self.current_stage_id != STAGE_CROSS_TOOL:
            self.current_stage_id = STAGE_CROSS_TOOL
        self.mobsf_run_in_progress = True
        if self.mobsf_progress_label and self.mobsf_progress_bar:
            self.mobsf_progress_label.setText("Starting MobSF analysis")
            self.mobsf_progress_bar.setMaximum(1)
            self.mobsf_progress_bar.setValue(0)
        self._append_mobsf_log("Starting MobSF Stage3 analysis...")
        self._set_mobsf_status("Running Stage3...")
        self._set_mobsf_scan_status("Starting...")
        if self.mobsf_run_button:
            self.mobsf_run_button.setEnabled(False)
        self._update_action_states()

        config = Stage3Config()
        config.enable_quark = False
        self.mobsf_run_worker = Stage3Worker(self.storage, self.current_project.project_id, config)
        self.mobsf_run_worker.progress.connect(self._handle_mobsf_progress)
        self.mobsf_run_worker.finished.connect(self._on_mobsf_run_finished)
        self.mobsf_run_worker.failed.connect(self._on_mobsf_run_failed)
        self.mobsf_run_worker.start()

    def _on_mobsf_run_finished(self, run: Run) -> None:
        self.mobsf_run_in_progress = False
        self.current_run = run
        self.current_run_dir = self.storage.get_run_dir(run.project_id, run.run_id)
        self.status_badge.setText(run.status)
        self.project_run_label.setText(run.finished_at or run.started_at)
        self._append_mobsf_log("Stage3 MobSF run completed.")
        if self.mobsf_progress_label and self.mobsf_progress_bar:
            self.mobsf_progress_label.setText("MobSF analysis completed")
            self.mobsf_progress_bar.setValue(self.mobsf_progress_bar.maximum())
        self._set_mobsf_scan_status("Completed")
        self._update_mobsf_summary()
        self._load_latest_run()
        self._update_action_states()

    def _on_mobsf_run_failed(self, message: str) -> None:
        self.mobsf_run_in_progress = False
        self._set_mobsf_status("Stage3 failed")
        self._append_mobsf_log("Stage3 MobSF run failed.")
        if self.mobsf_progress_label and self.mobsf_progress_bar:
            self.mobsf_progress_label.setText("MobSF analysis failed")
            self.mobsf_progress_bar.setValue(0)
        self._set_mobsf_scan_status("Failed")
        self._update_mobsf_summary()
        self._load_latest_run()
        self._update_action_states()
        QMessageBox.warning(self, "MobSF Stage3 failed", message)

    def _run_quark_analysis(self) -> None:
        if self.quark_run_in_progress:
            return
        if not self.current_project or not self.current_project.apk_meta:
            QMessageBox.warning(self, "Quark", "Select a project with an APK first.")
            return
        if self.current_stage_id != STAGE_CROSS_TOOL:
            self.current_stage_id = STAGE_CROSS_TOOL
        self.quark_run_in_progress = True
        if self.quark_log_view:
            self.quark_log_view.clear()
        self._append_quark_log("Starting Quark Stage3 analysis...")
        if self.quark_progress_label and self.quark_progress_bar:
            self.quark_progress_label.setText("Starting Quark analysis")
            self.quark_progress_bar.setMaximum(1)
            self.quark_progress_bar.setValue(0)
        if self.quark_status_label:
            self.quark_status_label.setText("Running")
        if self.quark_run_button:
            self.quark_run_button.setEnabled(False)
        self._update_action_states()

        config = Stage3QuarkConfig()
        self.quark_run_worker = Stage3QuarkWorker(self.storage, self.current_project.project_id, config)
        self.quark_run_worker.progress.connect(self._append_quark_log)
        self.quark_run_worker.finished.connect(self._on_quark_run_finished)
        self.quark_run_worker.failed.connect(self._on_quark_run_failed)
        self.quark_run_worker.start()

    def _run_apkid_analysis(self) -> None:
        if self.apkid_run_in_progress:
            return
        if not self.current_project or not self.current_project.apk_meta:
            QMessageBox.warning(self, "APKiD", "Select a project with an APK first.")
            return
        if self.current_stage_id != STAGE_CROSS_TOOL:
            self.current_stage_id = STAGE_CROSS_TOOL
        self.apkid_run_in_progress = True
        if self.apkid_progress_label and self.apkid_progress_bar:
            self.apkid_progress_label.setText("Starting APKiD analysis")
            self.apkid_progress_bar.setMaximum(1)
            self.apkid_progress_bar.setValue(0)
        if self.apkid_status_label:
            self.apkid_status_label.setText("Running")
        if self.apkid_log_view:
            self.apkid_log_view.setPlainText("")
        self._update_action_states()

        config = Stage3ApkidConfig()
        self.apkid_run_worker = Stage3ApkidWorker(
            self.storage,
            self.current_project.project_id,
            config,
        )
        self.apkid_run_worker.progress.connect(self._append_apkid_log)
        self.apkid_run_worker.finished.connect(self._on_apkid_run_finished)
        self.apkid_run_worker.failed.connect(self._on_apkid_run_failed)
        self.apkid_run_worker.start()

    def _run_apkleaks_analysis(self) -> None:
        if self.apkleaks_run_in_progress:
            return
        if not self.current_project or not self.current_project.apk_meta:
            QMessageBox.warning(self, "APKLeaks", "Select a project with an APK first.")
            return
        if self.current_stage_id != STAGE_CROSS_TOOL:
            self.current_stage_id = STAGE_CROSS_TOOL
        self.apkleaks_run_in_progress = True
        if self.apkleaks_progress_label and self.apkleaks_progress_bar:
            self.apkleaks_progress_label.setText("Starting APKLeaks analysis")
            self.apkleaks_progress_bar.setMaximum(1)
            self.apkleaks_progress_bar.setValue(0)
        if self.apkleaks_status_label:
            self.apkleaks_status_label.setText("Running")
        if self.apkleaks_log_view:
            self.apkleaks_log_view.setPlainText("")
        self._update_action_states()

        config = Stage3ApkleaksConfig()
        self.apkleaks_run_worker = Stage3ApkleaksWorker(
            self.storage,
            self.current_project.project_id,
            config,
        )
        self.apkleaks_run_worker.progress.connect(self._append_apkleaks_log)
        self.apkleaks_run_worker.finished.connect(self._on_apkleaks_run_finished)
        self.apkleaks_run_worker.failed.connect(self._on_apkleaks_run_failed)
        self.apkleaks_run_worker.start()

    def _on_quark_run_finished(self, run: Run) -> None:
        self.quark_run_in_progress = False
        self.current_run = run
        self.current_run_dir = self.storage.get_run_dir(run.project_id, run.run_id)
        self.status_badge.setText(run.status)
        self.project_run_label.setText(run.finished_at or run.started_at)
        self._append_quark_log("Stage3 Quark run completed.")
        if self.quark_progress_label and self.quark_progress_bar:
            self.quark_progress_label.setText("Quark analysis completed")
            self.quark_progress_bar.setValue(self.quark_progress_bar.maximum())
        if self.quark_status_label:
            self.quark_status_label.setText("Completed")
        self._update_mobsf_summary()
        self._load_latest_run()
        self._update_action_states()

    def _on_quark_run_failed(self, message: str) -> None:
        self.quark_run_in_progress = False
        if self.quark_status_label:
            self.quark_status_label.setText("Failed")
        self._append_quark_log("Stage3 Quark run failed.")
        if self.quark_progress_label and self.quark_progress_bar:
            self.quark_progress_label.setText("Quark analysis failed")
            self.quark_progress_bar.setValue(0)
        self._update_mobsf_summary()
        self._load_latest_run()
        self._update_action_states()
        QMessageBox.warning(self, "Quark Stage3 failed", message)

    def _on_apkid_run_finished(self, run: Run) -> None:
        self.apkid_run_in_progress = False
        self.current_run = run
        self.current_run_dir = self.storage.get_run_dir(run.project_id, run.run_id)
        self.status_badge.setText(run.status)
        self.project_run_label.setText(run.finished_at or run.started_at)
        if self.apkid_status_label:
            self.apkid_status_label.setText("Finished")
        if self.apkid_progress_label and self.apkid_progress_bar:
            self.apkid_progress_label.setText("APKiD analysis completed")
            self.apkid_progress_bar.setValue(self.apkid_progress_bar.maximum())
        self._load_latest_run()
        self._update_apkid_summary()
        self._render_apkid_log_view()
        self._update_action_states()

    def _on_apkid_run_failed(self, message: str) -> None:
        self.apkid_run_in_progress = False
        if self.apkid_status_label:
            self.apkid_status_label.setText("Failed")
        if self.apkid_progress_label and self.apkid_progress_bar:
            self.apkid_progress_label.setText("APKiD analysis failed")
            self.apkid_progress_bar.setValue(0)
        self._load_latest_run()
        self._update_apkid_summary()
        self._render_apkid_log_view()
        self._update_action_states()
        QMessageBox.warning(self, "APKiD Stage3 failed", message)

    def _on_apkleaks_run_finished(self, run: Run) -> None:
        self.apkleaks_run_in_progress = False
        self.current_run = run
        self.current_run_dir = self.storage.get_run_dir(run.project_id, run.run_id)
        self.status_badge.setText(run.status)
        self.project_run_label.setText(run.finished_at or run.started_at)
        if self.apkleaks_status_label:
            self.apkleaks_status_label.setText("Finished")
        if self.apkleaks_progress_label and self.apkleaks_progress_bar:
            self.apkleaks_progress_label.setText("APKLeaks analysis completed")
            self.apkleaks_progress_bar.setValue(self.apkleaks_progress_bar.maximum())
        self._load_latest_run()
        self._update_apkleaks_summary()
        self._render_apkleaks_log_view()
        self._update_action_states()

    def _on_apkleaks_run_failed(self, message: str) -> None:
        self.apkleaks_run_in_progress = False
        if self.apkleaks_status_label:
            self.apkleaks_status_label.setText("Failed")
        if self.apkleaks_progress_label and self.apkleaks_progress_bar:
            self.apkleaks_progress_label.setText("APKLeaks analysis failed")
            self.apkleaks_progress_bar.setValue(0)
        self._load_latest_run()
        self._update_apkleaks_summary()
        self._render_apkleaks_log_view()
        self._update_action_states()
        QMessageBox.warning(self, "APKLeaks Stage3 failed", message)

    def refresh_projects(self) -> None:
        self.project_list.clear()
        for project in self.storage.list_projects():
            name = project.project_id
            suffix = "No APK" if project.apk_meta is None else f"APK: {project.apk_meta.name}"
            item = QListWidgetItem(f"{name}\n{suffix}")
            item.setData(Qt.UserRole, project.project_id)
            self.project_list.addItem(item)
        self._filter_projects(self.project_search.text())

    def _filter_projects(self, text: str) -> None:
        query = (text or "").lower()
        for index in range(self.project_list.count()):
            item = self.project_list.item(index)
            item.setHidden(query not in item.text().lower())

    def _show_project_context_menu(self, pos) -> None:
        item = self.project_list.itemAt(pos)
        if not item:
            return
        project_id = item.data(Qt.UserRole)
        menu = QMenu(self)
        delete_action = menu.addAction("Delete project")
        delete_action.setEnabled(not self.analysis_running)
        action = menu.exec(self.project_list.viewport().mapToGlobal(pos))
        if action == delete_action:
            self._delete_project(project_id)

    def _delete_project(self, project_id: str) -> None:
        if self.analysis_running:
            QMessageBox.information(self, "Delete project", "Stop analysis before deleting.")
            return
        confirm = QMessageBox.question(
            self,
            "Delete project",
            f"Delete project \"{project_id}\"?\nThis will remove all versions, runs, and artifacts.",
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.storage.delete_project(project_id)
        except (FileNotFoundError, ValueError, OSError) as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return
        if self.current_project and self.current_project.project_id == project_id:
            self._set_current_project(None)
        self.refresh_projects()

    def _on_project_selected(self) -> None:
        selected = self.project_list.selectedItems()
        if not selected:
            self._set_current_project(None)
            return
        project_id = selected[0].data(Qt.UserRole)
        try:
            project = self.storage.load_project(project_id)
        except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return
        self._set_current_project(project)

    def _set_current_project(self, project: Project | None) -> None:
        self.current_project = project
        self.current_project_dir = None
        self.current_run = None
        self.current_run_dir = None
        self._update_tool_statuses(None)

        if not project:
            self._set_elided_label(self.project_name, "No project selected")
            self._set_elided_label(self.project_id_label, "-")
            self._set_elided_label(self.project_path_label, "-")
            self._set_elided_label(self.project_apk_label, "-")
            self._set_elided_label(self.project_hash_label, "-")
            self.project_size_label.setText("-")
            self.project_imported_label.setText("-")
            self.project_run_label.setText("-")
            self._populate_apk_versions(None)
            self.status_badge.setText("Idle")
            self._clear_run_views()
            self._clear_stage3_views()
            self._update_action_states()
            return

        self.current_project_dir = self.storage.get_project_dir(project.project_id)
        apk_path = self.storage.get_apk_path(project.project_id)
        display_name = project.project_id
        self._set_elided_label(self.project_name, display_name)
        self._set_elided_label(self.project_id_label, project.project_id)
        self._set_elided_label(self.project_path_label, str(self.current_project_dir))
        if project.apk_meta:
            self._set_elided_label(self.project_apk_label, str(apk_path))
            self._set_elided_label(self.project_hash_label, project.apk_meta.sha256)
            self.project_size_label.setText(self._format_size(project.apk_meta.size))
            self.project_imported_label.setText(project.apk_meta.imported_at)
        else:
            self._set_elided_label(self.project_apk_label, "-")
            self._set_elided_label(self.project_hash_label, "-")
            self.project_size_label.setText("-")
            self.project_imported_label.setText("-")
        self._populate_apk_versions(project)

        self._load_latest_run()
        self._update_action_states()

    def _load_latest_run(self) -> None:
        if not self.current_project:
            return
        stage = self._resolved_run_stage()
        if stage == STAGE_CROSS_TOOL:
            latest_stage3 = self._find_latest_stage3_run()
            self.current_run = None
            self.current_run_dir = latest_stage3[0] if latest_stage3 else None
            if not latest_stage3:
                self.project_run_label.setText("-")
                self.status_badge.setText("Idle")
                self._clear_run_views()
                self._load_stage3_run_views()
                return
            _, run_data = latest_stage3
            finished_at = run_data.get("finished_at")
            started_at = run_data.get("started_at")
            self.project_run_label.setText(finished_at or started_at or "-")
            self.status_badge.setText("Done" if finished_at else "Running")
            self._clear_run_views()
            self._load_stage3_run_views()
            return
        latest = self.storage.get_latest_run(self.current_project.project_id, stage)
        if not latest:
            self.current_run = None
            self.current_run_dir = None
            self.project_run_label.setText("-")
            self.status_badge.setText("Idle")
            self._clear_run_views()
            if self.current_stage_id == STAGE_CROSS_TOOL:
                self._load_stage3_run_views()
            return
        self.current_run, self.current_run_dir = latest
        if self._is_run_stale(self.current_run):
            self.current_run = None
            self.current_run_dir = None
            self.project_run_label.setText("-")
            self.status_badge.setText("Idle")
            self._clear_run_views()
            if self.current_stage_id == STAGE_CROSS_TOOL:
                self._load_stage3_run_views()
            return
        self.status_badge.setText(self.current_run.status)
        self.project_run_label.setText(self.current_run.finished_at or self.current_run.started_at)
        self._load_run_views()
        self._update_tool_statuses(self.current_run)
        if self.current_stage_id == STAGE_CROSS_TOOL:
            self._load_stage3_run_views()

    def _find_latest_stage3_run(self) -> tuple[Path, dict] | None:
        if not self.current_project:
            return None
        version_dir = self.storage.get_active_version_dir(self.current_project.project_id)
        runs_dir = version_dir / "runs"
        if not runs_dir.exists():
            return None
        active_apk_path = self.storage.get_apk_path(self.current_project.project_id)
        run_dirs = [path for path in runs_dir.iterdir() if path.is_dir()]
        run_dirs.sort(key=lambda path: path.name, reverse=True)
        for run_dir in run_dirs:
            run_path = run_dir / "run.json"
            if not run_path.exists():
                continue
            try:
                data = json.loads(run_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("schema") != "tapka.run.v1":
                continue
            if data.get("stage") != "stage3":
                continue
            input_meta = data.get("input") or {}
            input_apk = input_meta.get("apk_path")
            if input_apk and str(active_apk_path) != input_apk:
                continue
            return run_dir, data
        return None

    def _clear_run_views(self) -> None:
        self.findings = []
        if self.findings_table:
            self._populate_findings_table([])
        if self.log_view:
            self._load_logs([])
        if self.artifacts_table:
            self._load_artifacts([])
        self._update_tool_statuses(None)

    def _load_run_views(self) -> None:
        if not self.current_run or not self.current_run_dir:
            self._clear_run_views()
            return
        self.findings = self._load_findings()
        if self.findings_table:
            self._apply_findings_filters()
        if self.log_view:
            self._load_logs()
        if self.artifacts_table:
            self._load_artifacts()

    def _clear_stage3_views(self) -> None:
        self.stage3_run_dir = None
        self.stage3_run_data = None
        self.stage3_findings = []
        self._update_stage3_overview_metrics()
        self._populate_stage3_findings_table([])
        self._load_stage3_logs([])
        self._load_stage3_artifacts([])
        if self.mobsf_progress_label and self.mobsf_progress_bar:
            self.mobsf_progress_label.setText("Ready")
            self.mobsf_progress_bar.setMaximum(1)
            self.mobsf_progress_bar.setValue(0)
        if self.quark_progress_label and self.quark_progress_bar:
            self.quark_progress_label.setText("Ready")
            self.quark_progress_bar.setMaximum(1)
            self.quark_progress_bar.setValue(0)
        if self.apkid_progress_label and self.apkid_progress_bar:
            self.apkid_progress_label.setText("Ready")
            self.apkid_progress_bar.setMaximum(1)
            self.apkid_progress_bar.setValue(0)
        if self.apkid_status_label:
            self.apkid_status_label.setText("Ready")
        if self.apkid_summary_label:
            self.apkid_summary_label.setText("-")
        if self.apkid_summary_updated:
            self.apkid_summary_updated.setText("-")
        if self.apkid_log_view:
            self.apkid_log_view.setPlainText("")
        if self.apkleaks_progress_label and self.apkleaks_progress_bar:
            self.apkleaks_progress_label.setText("Ready")
            self.apkleaks_progress_bar.setMaximum(1)
            self.apkleaks_progress_bar.setValue(0)
        if self.apkleaks_status_label:
            self.apkleaks_status_label.setText("Ready")
        if self.apkleaks_summary_label:
            self.apkleaks_summary_label.setText("-")
        if self.apkleaks_summary_updated:
            self.apkleaks_summary_updated.setText("-")
        if self.apkleaks_log_view:
            self.apkleaks_log_view.setPlainText("")

    def _load_stage3_run_views(self) -> None:
        if not self.current_project:
            self._clear_stage3_views()
            return
        latest = self._find_latest_stage3_run()
        if not latest:
            self._clear_stage3_views()
            return
        self.stage3_run_dir, self.stage3_run_data = latest
        self.stage3_findings = self._load_stage3_findings()
        self._update_stage3_overview_metrics()
        self._apply_stage3_findings_filters()
        self._load_stage3_logs()
        self._load_stage3_artifacts()
        self._render_apkleaks_log_view()
        self._render_apkid_log_view()
        self._update_apkid_summary()
        self._update_apkleaks_summary()


    def _update_stage3_overview_metrics(self) -> None:
        labels = [
            self.stage3_metric_updated,
            self.stage3_metric_tools,
            self.stage3_metric_findings,
            self.stage3_metric_quark,
            self.stage3_metric_mobsf,
            self.stage3_metric_kinds,
        ]
        if any(label is None for label in labels):
            return
        self.stage3_metric_updated.setText("No Stage3 runs yet")
        self.stage3_metric_tools.setText("-")
        self.stage3_metric_findings.setText("-")
        self.stage3_metric_quark.setText("-")
        self.stage3_metric_mobsf.setText("-")
        self.stage3_metric_kinds.setText("-")
        if not self.stage3_run_dir or not self.stage3_run_data:
            return

        finished_at = self.stage3_run_data.get("finished_at") or self.stage3_run_data.get("started_at") or "-"
        self.stage3_metric_updated.setText(finished_at)

        tools = self.stage3_run_data.get("tools")
        if isinstance(tools, list):
            self.stage3_metric_tools.setText(str(len(tools)))
        else:
            tools_dir = self.stage3_run_dir / "tools"
            tool_count = 0
            if tools_dir.exists():
                tool_count = sum(1 for path in tools_dir.iterdir() if path.is_dir())
            self.stage3_metric_tools.setText(str(tool_count))

        self.stage3_metric_findings.setText(str(len(self.stage3_findings)))

        quark_status = self._stage3_tool_status("quark")
        mobsf_status = self._stage3_tool_status("mobsf")
        self.stage3_metric_quark.setText(quark_status)
        self.stage3_metric_mobsf.setText(mobsf_status)

        kinds: dict[str, int] = {}
        for item in self.stage3_findings:
            kind = item.get("kind")
            if kind:
                kinds[kind] = kinds.get(kind, 0) + 1
        if kinds:
            parts = [f"{name}:{count}" for name, count in sorted(kinds.items())]
            self.stage3_metric_kinds.setText(", ".join(parts))

    def _update_mobsf_summary(self) -> None:
        labels = [
            self.mobsf_summary_score,
            self.mobsf_summary_high,
            self.mobsf_summary_warning,
            self.mobsf_summary_trackers,
            self.mobsf_summary_updated,
        ]
        if any(label is None for label in labels):
            return
        self.mobsf_summary_score.setText("-")
        self.mobsf_summary_high.setText("-")
        self.mobsf_summary_warning.setText("-")
        self.mobsf_summary_trackers.setText("-")
        self.mobsf_summary_updated.setText("-")
        if self.quark_status_label:
            self.quark_status_label.setText("Not configured")
        if self.quark_rules_label:
            self.quark_rules_label.setText("-")
        if self.quark_summary_total:
            self.quark_summary_total.setText("-")
        if self.quark_summary_matched:
            self.quark_summary_matched.setText("-")
        if self.quark_summary_updated:
            self.quark_summary_updated.setText("-")
        if self.stage3_report_status:
            self.stage3_report_status.setText("-")
        if self.stage3_report_updated:
            self.stage3_report_updated.setText("-")
        if not self.current_project:
            return
        latest = self._find_latest_stage3_run()
        run_dir, run_data = latest if latest else (None, None)
        finished = None
        if run_data:
            finished = run_data.get("finished_at") or run_data.get("started_at")
        if not run_dir:
            self._update_quark_rules_status()
            return
        report_status = "Ready"
        report_path = run_dir / "artifacts" / "stage3_report.json"
        if not report_path.exists():
            self._update_quark_rules_status()
            return
        if self.stage3_report_status:
            self.stage3_report_status.setText(report_status)
        if self.stage3_report_updated and finished:
            self.stage3_report_updated.setText(finished)
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self._update_quark_rules_status()
            return
        if data.get("schema") == "tapka.report.v2":
            tools_list = data.get("tools") or []
            findings_list = data.get("findings") or []
            mobsf_tool = next((t for t in tools_list if t.get("tool") == "mobsf"), None)
            if mobsf_tool:
                metrics = mobsf_tool.get("metrics") or {}
                score = metrics.get("security_score")
                if isinstance(score, (int, float)):
                    self.mobsf_summary_score.setText(f"{int(score)}/100")
                tool_finished = mobsf_tool.get("finished_at")
                if isinstance(tool_finished, str) and tool_finished:
                    self.mobsf_summary_updated.setText(tool_finished)
                elif finished:
                    self.mobsf_summary_updated.setText(finished)
                high_count = sum(
                    1 for f in findings_list
                    if f.get("severity") == "high"
                    and any(s.get("tool") == "mobsf" for s in (f.get("sources") or []))
                )
                med_count = sum(
                    1 for f in findings_list
                    if f.get("severity") == "medium"
                    and any(s.get("tool") == "mobsf" for s in (f.get("sources") or []))
                )
                self.mobsf_summary_high.setText(str(high_count))
                self.mobsf_summary_warning.setText(str(med_count))
            quark_tool = next((t for t in tools_list if t.get("tool") == "quark"), None)
            if quark_tool:
                metrics = quark_tool.get("metrics") or {}
                rules_total = metrics.get("rules_total")
                rules_matched = metrics.get("rules_matched")
                if self.quark_summary_total and isinstance(rules_total, int):
                    self.quark_summary_total.setText(str(rules_total))
                if self.quark_summary_matched and isinstance(rules_matched, int):
                    self.quark_summary_matched.setText(str(rules_matched))
                tool_finished = quark_tool.get("finished_at")
                if self.quark_summary_updated:
                    if isinstance(tool_finished, str) and tool_finished:
                        self.quark_summary_updated.setText(tool_finished)
                    elif finished:
                        self.quark_summary_updated.setText(finished)
            self._update_quark_rules_status()
        else:
            mobsf = data.get("mobsf") or {}
            static = mobsf.get("static") or {}
            score = static.get("security_score")
            if isinstance(score, (int, float)):
                self.mobsf_summary_score.setText(f"{int(score)}/100")
            appsec_summary = static.get("appsec_summary") or {}
            high = appsec_summary.get("high")
            warning = appsec_summary.get("warning")
            if isinstance(high, int):
                self.mobsf_summary_high.setText(str(high))
            elif isinstance(static.get("appsec_high"), list):
                self.mobsf_summary_high.setText(str(len(static.get("appsec_high", []))))
            if isinstance(warning, int):
                self.mobsf_summary_warning.setText(str(warning))
            elif isinstance(static.get("appsec_warning"), list):
                self.mobsf_summary_warning.setText(str(len(static.get("appsec_warning", []))))
            trackers_detected = static.get("trackers_detected")
            trackers_total = static.get("trackers_total")
            if isinstance(trackers_detected, int) and isinstance(trackers_total, int):
                self.mobsf_summary_trackers.setText(f"{trackers_detected}/{trackers_total}")
            elif isinstance(trackers_total, int):
                self.mobsf_summary_trackers.setText(str(trackers_total))
            report_finished = (data.get("run") or {}).get("finished_at")
            if isinstance(report_finished, str) and report_finished:
                self.mobsf_summary_updated.setText(report_finished)
            elif finished:
                self.mobsf_summary_updated.setText(finished)
            quark = data.get("quark") or {}
            summary = quark.get("summary") or {}
            if self.quark_summary_total and isinstance(summary.get("rules_total"), int):
                self.quark_summary_total.setText(str(summary.get("rules_total")))
            if self.quark_summary_matched and isinstance(summary.get("rules_matched"), int):
                self.quark_summary_matched.setText(str(summary.get("rules_matched")))
            if self.quark_summary_updated and finished:
                self.quark_summary_updated.setText(finished)
            self._update_quark_rules_status(quark.get("rules_dir"))

    def _update_apkid_summary(self) -> None:
        labels = [
            self.apkid_status_label,
            self.apkid_summary_label,
            self.apkid_summary_updated,
        ]
        if any(label is None for label in labels):
            return
        self.apkid_status_label.setText("Ready")
        self.apkid_summary_label.setText("-")
        self.apkid_summary_updated.setText("-")
        if not self.stage3_run_dir:
            return
        result_path = self.stage3_run_dir / "tools" / "apkid" / "tool_result.json"
        if result_path.exists():
            try:
                data = json.loads(result_path.read_text(encoding="utf-8"))
                ok = data.get("ok")
                exit_code = data.get("exit_code")
                status = "OK" if ok is True else "FAIL" if ok is False else "Ready"
                if isinstance(exit_code, int):
                    status = f"{status} ({exit_code})"
                self.apkid_status_label.setText(status)
                finished_at = data.get("finished_at") or data.get("started_at")
                if isinstance(finished_at, str) and finished_at:
                    self.apkid_summary_updated.setText(finished_at)
            except (json.JSONDecodeError, OSError):
                pass
        raw_path = self.stage3_run_dir / "tools" / "apkid" / "raw" / "apkid.json"
        if not raw_path.exists():
            return
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            return
        files = payload.get("files") or payload.get("file") or []
        if isinstance(files, dict):
            files = [files]
        total = 0
        if isinstance(files, list):
            for file_entry in files:
                if not isinstance(file_entry, dict):
                    continue
                matches = file_entry.get("matches") or {}
                if not isinstance(matches, dict):
                    continue
                for values in matches.values():
                    if values is None:
                        continue
                    if isinstance(values, list):
                        total += len(values)
                    else:
                        total += 1
        if total:
            self.apkid_summary_label.setText(str(total))

    def _update_apkleaks_summary(self) -> None:
        labels = [
            self.apkleaks_status_label,
            self.apkleaks_summary_label,
            self.apkleaks_summary_updated,
        ]
        if any(label is None for label in labels):
            return
        self.apkleaks_summary_label.setText("-")
        self.apkleaks_summary_updated.setText("-")
        if not self.stage3_run_dir:
            return
        result_path = self.stage3_run_dir / "tools" / "apkleaks" / "tool_result.json"
        if result_path.exists():
            try:
                data = json.loads(result_path.read_text(encoding="utf-8"))
                ok = data.get("ok")
                exit_code = data.get("exit_code")
                status = "OK" if ok is True else "FAIL" if ok is False else "Ready"
                if isinstance(exit_code, int):
                    status = f"{status} ({exit_code})"
                self.apkleaks_status_label.setText(status)
                finished_at = data.get("finished_at") or data.get("started_at")
                if isinstance(finished_at, str) and finished_at:
                    self.apkleaks_summary_updated.setText(finished_at)
            except (json.JSONDecodeError, OSError):
                pass
        raw_path = self.stage3_run_dir / "tools" / "apkleaks" / "raw" / "apkleaks.json"
        if not raw_path.exists():
            return
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            return
        count = 0
        if isinstance(payload, list):
            count = len(payload)
        elif isinstance(payload, dict):
            findings = payload.get("findings")
            if isinstance(findings, list):
                count = len(findings)
            else:
                count = len(payload)
        if count:
            self.apkleaks_summary_label.setText(str(count))

    def _update_quark_rules_status(self, rules_dir_override: str | None = None) -> None:
        if not self.quark_status_label or not self.quark_rules_label:
            return
        rules_dir = Path(rules_dir_override) if rules_dir_override else (Path(__file__).resolve().parents[1] / ".tapka" / "quark-rules")
        if not rules_dir.exists():
            self.quark_status_label.setText("Missing")
            self.quark_rules_label.setText(str(rules_dir))
            return
        rule_count = 0
        for path in rules_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in (".json", ".yml", ".yaml"):
                rule_count += 1
        status = "Ready" if rule_count else "Empty"
        self.quark_status_label.setText(status)
        self.quark_rules_label.setText(f"{rule_count} rules")

    def _create_project(self, _checked: bool = False) -> None:
        if self.analysis_running:
            return
        name, ok = QInputDialog.getText(self, "New Project", "Project name:")
        if not ok:
            return
        name = name.strip()
        if not name:
            QMessageBox.warning(self, "Error", "Project name cannot be empty.")
            return
        try:
            project = self.storage.create_project_with_name(name)
        except (FileExistsError, ValueError, OSError) as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return
        self.refresh_projects()
        self._select_project(project.project_id)

    def _add_apk(self, _checked: bool = False) -> None:
        if self.analysis_running:
            return
        apk_file, _ = QFileDialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk)")
        if not apk_file:
            return
        if not self.current_project:
            QMessageBox.warning(self, "Error", "Create a project first.")
            return
        try:
            project = self.storage.add_apk_to_project(self.current_project.project_id, apk_file)
        except (FileNotFoundError, ValueError, OSError) as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return
        self.refresh_projects()
        self._select_project(project.project_id)
        self._set_current_project(project)

    def _select_project(self, project_id: str) -> None:
        for i in range(self.project_list.count()):
            item = self.project_list.item(i)
            if item.data(Qt.UserRole) == project_id:
                self.project_list.setCurrentItem(item)
                break

    def _on_stage_changed(self, index: int) -> None:
        if index < 0 or index >= len(self.stage_ids):
            return
        self.current_stage_id = self.stage_ids[index]
        self._load_latest_run()
        if self.current_stage_id == STAGE_CROSS_TOOL:
            self._update_mobsf_summary()
            self._update_apkid_summary()
            self._update_apkleaks_summary()
        self._update_action_states()

    def _on_stage3_mode_changed(self, index: int) -> None:
        if not self.stage3_stack:
            return
        if index < 0 or index >= self.stage3_stack.count():
            return
        self.stage3_stack.setCurrentIndex(index)

    def _resolved_run_stage(self) -> str:
        if self.current_stage_id == STAGE_OVERALL:
            return STAGE_STATIC
        return self.current_stage_id

    def _open_project_folder_from_item(self, item: QListWidgetItem) -> None:
        project_id = item.data(Qt.UserRole)
        if not project_id:
            return
        project_dir = self.storage.get_project_dir(project_id)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(project_dir)))

    def _open_project_folder(self) -> None:
        if not self.current_project_dir:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.current_project_dir)))

    def _populate_apk_versions(self, project: Project | None) -> None:
        self.apk_version_combo.blockSignals(True)
        self.apk_version_combo.clear()

        if not project or not project.apk_meta:
            self.apk_version_combo.addItem("No versions")
            self.apk_version_combo.setEnabled(False)
            self.apk_version_combo.blockSignals(False)
            return

        versions = project.apk_versions or [project.apk_meta]
        for meta in versions:
            label = f"{meta.imported_at} · {meta.name} · {meta.sha256[:8]}"
            self.apk_version_combo.addItem(label, meta.sha256)

        active_sha = project.active_apk_sha256 or project.apk_meta.sha256
        index = 0
        for i in range(self.apk_version_combo.count()):
            if self.apk_version_combo.itemData(i) == active_sha:
                index = i
                break
        self.apk_version_combo.setCurrentIndex(index)
        self.apk_version_combo.setEnabled(len(versions) > 1)
        self.apk_version_combo.blockSignals(False)

    def _on_version_changed(self) -> None:
        if not self.current_project or not self.current_project.apk_meta:
            return
        sha256 = self.apk_version_combo.currentData()
        if not sha256 or sha256 == self.current_project.apk_meta.sha256:
            return
        try:
            project = self.storage.set_active_apk_version(self.current_project.project_id, sha256)
        except (FileNotFoundError, ValueError, OSError) as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return
        self._set_current_project(project)

    def _run_analysis(self) -> None:
        if (
            self.analysis_running
            or not self.current_project
            or not self.current_project.apk_meta
            or self.current_stage_id != STAGE_STATIC
        ):
            return
        self.analysis_running = True
        self._analysis_start_ts = time.monotonic()
        self._analysis_message = "Starting analysis"
        self._analysis_step_text = "0/0"
        self._focus_logs_tab()
        if self.log_view:
            self.log_view.setPlainText("")
        self.log_paths.clear()
        if self._analysis_timer:
            self._analysis_timer.start()
        self.status_badge.setText("Running")
        self.progress_label.setText("Starting analysis")
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self._update_tool_statuses(None, running=True)
        self._update_action_states()

        self.worker = Stage1Worker(self.storage, self.current_project.project_id)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_run_finished)
        self.worker.failed.connect(self._on_run_failed)
        self.worker.start()

    def _focus_logs_tab(self) -> None:
        if self.stage_tabs and self.stage_tabs.currentIndex() != 0:
            self.stage_tabs.setCurrentIndex(0)
        if self.tabs:
            self.tabs.setCurrentIndex(1)
        self._render_log_view()

    def _on_progress(self, payload: dict) -> None:
        completed = int(payload.get("completed", 0))
        total = int(payload.get("total", 0)) or 1
        message = payload.get("message", "Running...")
        elapsed_sec = payload.get("elapsed_sec")
        run_dir = payload.get("run_dir")

        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(min(completed, total))

        step_text = f"{completed}/{total}"
        self._analysis_message = message
        self._analysis_step_text = step_text
        if elapsed_sec is None:
            self.progress_label.setText(f"{message} · {step_text}")
        else:
            self.progress_label.setText(
                f"{message} · {step_text} · Elapsed {self._format_duration(elapsed_sec)}"
            )

        if run_dir:
            self._ensure_live_logs(Path(run_dir))
        if self.log_paths:
            self._render_log_view()
        elif self.log_view:
            self.log_view.appendPlainText(self.progress_label.text())

    def _on_run_finished(self, run: Run) -> None:
        self.analysis_running = False
        if self._analysis_timer:
            self._analysis_timer.stop()
        self._analysis_start_ts = None
        self.current_run = run
        self.current_run_dir = self.storage.get_run_dir(run.project_id, run.run_id)
        self.status_badge.setText(run.status)
        self.project_run_label.setText(run.finished_at or run.started_at)
        self.progress_label.setText("Analysis completed")
        self.progress_bar.setValue(self.progress_bar.maximum())
        self._load_run_views()
        self._update_tool_statuses(run)
        self._update_action_states()

    def _on_run_failed(self, message: str) -> None:
        self.analysis_running = False
        if self._analysis_timer:
            self._analysis_timer.stop()
        self._analysis_start_ts = None
        self.status_badge.setText("Error")
        self.progress_label.setText("Analysis failed. Check logs.")
        self._load_latest_run()
        self._update_tool_statuses(self.current_run)
        self._update_action_states()
        QMessageBox.warning(self, "Stage 1 Failed", message)

    def _open_report(self) -> None:
        resolved = self._report_paths(self.current_stage_id)
        if not resolved:
            return
        _, _, html_path = resolved
        if html_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(html_path)))
        else:
            QMessageBox.information(self, "Report", "Report not found. Generate it first.")

    def _open_stage1_run_dir(self) -> None:
        run_dir = None
        if self.current_stage_id == STAGE_STATIC and self.current_run_dir:
            run_dir = self.current_run_dir
        if not run_dir:
            run_dir = self._resolve_report_run_dir(STAGE_STATIC)
        if not run_dir:
            QMessageBox.information(self, "Analysis directory", "No Stage1 run found.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(run_dir)))

    def _open_stage3_report(self) -> None:
        if not self.current_project:
            return
        latest = self._find_latest_stage3_run()
        if not latest:
            QMessageBox.information(self, "Stage3 report", "No Stage3 run found yet.")
            return
        run_dir, _ = latest
        report_manager = ReportManager(self.storage)
        _, html_path = report_manager.report_paths(run_dir, STAGE_CROSS_TOOL)
        if html_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(html_path)))
        else:
            QMessageBox.information(self, "Stage3 report", "Report not found yet.")

    def _generate_report(self) -> None:
        if not self.current_project:
            return
        report_manager = ReportManager(self.storage)
        latest = self.storage.get_latest_run(self.current_project.project_id, STAGE_STATIC)
        if not latest:
            QMessageBox.information(self, "Report", "No Stage1 run found to generate reports.")
            return
        run, run_dir = latest
        html_path = report_manager.regenerate_stage1_from_json(run_dir)
        if html_path is None:
            findings = report_manager.load_findings(run, run_dir)
            if not findings:
                QMessageBox.warning(self, "Report", "No findings JSON found to regenerate Stage1 report.")
                return
            _, html_path = report_manager.generate_stage1(run, run_dir, findings)
        report_manager.ensure_stub_reports(run, run_dir)
        if html_path and html_path.exists():
            QMessageBox.information(self, "Report", "Reports generated successfully.")
        self._update_action_states()

    def _generate_stage3_report(self) -> None:
        if not self.current_project:
            return
        latest = self._find_latest_stage3_run()
        if not latest:
            QMessageBox.information(self, "Stage3 report", "No Stage3 run found to generate reports.")
            return
        run_dir, _ = latest
        report_manager = ReportManager(self.storage)
        json_path, html_path = report_manager.report_paths(run_dir, STAGE_CROSS_TOOL)
        if not json_path.exists():
            QMessageBox.information(self, "Stage3 report", "Stage3 report JSON not found.")
            return
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            report = ReportV2.model_validate(data)
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            QMessageBox.warning(self, "Stage3 report", str(exc))
            return
        html_path.write_text(render_report_html(report), encoding="utf-8")
        if html_path.exists():
            QMessageBox.information(self, "Stage3 report", "Stage3 report generated successfully.")
        self._update_action_states()

    def _report_paths(self, stage_id: str) -> tuple[Path, Path, Path] | None:
        run_dir = self._resolve_report_run_dir(stage_id)
        if not run_dir:
            return None
        report_manager = ReportManager(self.storage)
        json_path, html_path = report_manager.report_paths(run_dir, stage_id)
        return run_dir, json_path, html_path

    def _resolve_report_run_dir(self, stage_id: str) -> Path | None:
        if not self.current_project:
            return None
        stage_for_run = stage_id if stage_id != STAGE_OVERALL else STAGE_STATIC
        latest = self.storage.get_latest_run(self.current_project.project_id, stage_for_run)
        if latest:
            return latest[1]
        if stage_id != STAGE_STATIC:
            latest = self.storage.get_latest_run(self.current_project.project_id, STAGE_STATIC)
            if latest:
                return latest[1]
        return None

    def _report_available(self) -> bool:
        resolved = self._report_paths(self.current_stage_id)
        if not resolved:
            return False
        _, _, html_path = resolved
        return html_path.exists()

    def _stage3_report_ready(self) -> bool:
        if not self.current_project:
            return False
        latest = self._find_latest_stage3_run()
        if not latest:
            return False
        run_dir, _ = latest
        report_manager = ReportManager(self.storage)
        _, html_path = report_manager.report_paths(run_dir, STAGE_CROSS_TOOL)
        return html_path.exists()

    def _update_action_states(self) -> None:
        has_project = self.current_project is not None
        has_apk = False
        if has_project and self.current_project.apk_meta is not None:
            try:
                apk_path = self.storage.get_apk_path(self.current_project.project_id)
                has_apk = apk_path.exists() and apk_path.stat().st_size > 0
            except OSError:
                has_apk = False
        has_run = self.current_run is not None
        running = self.analysis_running
        on_static_stage = self.current_stage_id == STAGE_STATIC
        on_stage3 = self.current_stage_id == STAGE_CROSS_TOOL
        stage3_busy = (
            self.mobsf_run_in_progress
            or self.quark_run_in_progress
            or self.apkid_run_in_progress
            or self.apkleaks_run_in_progress
        )
        stage3_has_run = self.stage3_run_dir is not None

        self.project_list.setEnabled(not running)
        self.project_search.setEnabled(not running)
        self.new_project_button.setEnabled(not running)
        self.add_apk_button.setEnabled(has_project and not running)
        self.run_analysis_button.setEnabled(has_apk and not running and on_static_stage)
        self.open_project_folder_button.setEnabled(has_project)
        self.open_report_button.setEnabled(self._report_available() and not running)
        self.generate_report_button.setEnabled(
            has_project and not running and on_static_stage and not self._report_available()
        )

        if self.log_copy_button:
            self.log_copy_button.setEnabled(has_run)
        if self.log_save_button:
            self.log_save_button.setEnabled(has_run)
        if self.log_open_button:
            self.log_open_button.setEnabled(has_run)
        if self.artifacts_open_button:
            self.artifacts_open_button.setEnabled(has_run)
        if self.artifacts_reveal_button:
            self.artifacts_reveal_button.setEnabled(has_run)
        if self.stage3_log_copy_button:
            self.stage3_log_copy_button.setEnabled(stage3_has_run)
        if self.stage3_log_save_button:
            self.stage3_log_save_button.setEnabled(stage3_has_run)
        if self.stage3_log_open_button:
            self.stage3_log_open_button.setEnabled(stage3_has_run)
        if self.stage3_artifacts_open_button:
            self.stage3_artifacts_open_button.setEnabled(stage3_has_run)
        if self.stage3_artifacts_reveal_button:
            self.stage3_artifacts_reveal_button.setEnabled(stage3_has_run)
        if self.open_analysis_dir_button:
            self.open_analysis_dir_button.setEnabled(has_run and on_static_stage and not running)
        if self.apkleaks_run_button:
            self.apkleaks_run_button.setEnabled(has_apk and on_stage3 and not stage3_busy)
        if self.apkid_run_button:
            self.apkid_run_button.setEnabled(has_apk and on_stage3 and not stage3_busy)
        if self.apkid_report_button:
            self.apkid_report_button.setEnabled(
                on_stage3 and not stage3_busy and self._stage3_tool_ok("apkid")
            )
        if self.apkleaks_report_button:
            self.apkleaks_report_button.setEnabled(
                on_stage3 and not stage3_busy and self._stage3_tool_ok("apkleaks")
            )
        if self.mobsf_setup_button:
            self.mobsf_setup_button.setEnabled(
                not self.mobsf_setup_in_progress and not stage3_busy
            )
        if self.mobsf_stop_button:
            self.mobsf_stop_button.setEnabled(
                not self.mobsf_setup_in_progress and self.mobsf_running and not stage3_busy
            )
        if self.mobsf_run_button:
            can_run_stage3 = (
                has_apk
                and self.current_stage_id == STAGE_CROSS_TOOL
                and self.mobsf_running
            )
            self.mobsf_run_button.setEnabled(
                not stage3_busy and can_run_stage3
            )
        if self.quark_run_button:
            can_run_quark = has_apk and self.current_stage_id == STAGE_CROSS_TOOL
            self.quark_run_button.setEnabled(
                not stage3_busy and can_run_quark
            )
        if self.mobsf_open_report_button:
            stage3_ready = self._stage3_report_ready()
            self.mobsf_open_report_button.setEnabled(stage3_ready and not stage3_busy)
        if self.quark_open_report_button:
            stage3_ready = self._stage3_report_ready()
            self.quark_open_report_button.setEnabled(stage3_ready and not stage3_busy)
        if self.mobsf_open_dir_button:
            self.mobsf_open_dir_button.setEnabled(on_stage3 and stage3_has_run and not stage3_busy)
        if self.quark_open_dir_button:
            self.quark_open_dir_button.setEnabled(on_stage3 and stage3_has_run and not stage3_busy)
        if self.apkid_open_dir_button:
            self.apkid_open_dir_button.setEnabled(on_stage3 and stage3_has_run and not stage3_busy)
        if self.apkleaks_open_dir_button:
            self.apkleaks_open_dir_button.setEnabled(on_stage3 and stage3_has_run and not stage3_busy)

    def _set_tool_status(self, tool: str, status: str, text: str | None = None) -> None:
        button = self.tool_status_buttons.get(tool)
        if not button:
            return
        text_map = {
            "ok": "OK",
            "fail": "FAIL",
            "running": "Running",
            "partial": "PARTIAL",
            "pending": "Not run",
            "skipped": "Skipped",
            "unknown": "Unknown",
        }
        button.setText(text or text_map.get(status, status))
        button.setProperty("status", status)
        button.setCursor(Qt.PointingHandCursor if status == "fail" else Qt.ArrowCursor)
        button.style().unpolish(button)
        button.style().polish(button)

    def _update_tool_statuses(self, run: Run | None, running: bool = False) -> None:
        if running:
            for tool, _ in self.TOOL_STATUS_DEFS:
                self._set_tool_status(tool, "running")
            return
        if not run or not run.command_results:
            for tool, _ in self.TOOL_STATUS_DEFS:
                self._set_tool_status(tool, "pending")
            return
        for tool, _ in self.TOOL_STATUS_DEFS:
            results = [result for result in run.command_results if result.tool == tool]
            if not results:
                self._set_tool_status(tool, "skipped")
                continue
            statuses = [self._result_status(tool, result) for result in results]
            if "fail" in statuses:
                self._set_tool_status(tool, "fail")
            elif "partial" in statuses:
                self._set_tool_status(tool, "partial")
            elif "success" in statuses:
                self._set_tool_status(tool, "ok")
            else:
                self._set_tool_status(tool, "unknown")

    def _open_tool_stderr(self, tool: str) -> None:
        button = self.tool_status_buttons.get(tool)
        if not button or button.property("status") != "fail":
            return
        if not self.current_run or not self.current_run_dir:
            return
        results = [result for result in self.current_run.command_results if result.tool == tool]
        failing = [result for result in results if self._result_status(tool, result) == "fail"]
        if not failing:
            return
        stderr_path = Path(failing[0].stderr_path)
        if stderr_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(stderr_path)))
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.current_run_dir / "logs")))

    def _load_findings(self) -> list[dict]:
        if not self.current_run_dir:
            return []
        findings_path = self.current_run_dir / "findings" / "findings.json"
        if not findings_path.exists():
            return []
        try:
            payload = json.loads(findings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        items = []
        for entry in payload:
            category = entry.get("category", "unknown")
            match = entry.get("evidence") or entry.get("match", "")
            file_path = entry.get("file_path", "")
            line = entry.get("line")
            column = entry.get("column")
            location = entry.get("location") or file_path
            if not entry.get("location"):
                if line is not None:
                    location += f":{line}"
                    if column is not None:
                        location += f":{column}"
            severity_value = entry.get("severity")
            if severity_value:
                severity = severity_value.capitalize()
            else:
                severity = self.SEVERITY_MAP.get(category, "Medium")
            items.append(
                {
                    "severity": severity,
                    "category": category,
                    "title": self.CATEGORY_TITLE.get(category, category),
                    "location": location,
                    "evidence": match,
                    "file_path": file_path,
                    "line": line,
                    "column": column,
                }
            )
        return items

    def _load_stage3_findings(self) -> list[dict]:
        if not self.stage3_run_dir:
            return []
        indicators_path = self.stage3_run_dir / "normalized" / "indicators.json"
        if not indicators_path.exists():
            return []
        try:
            payload = json.loads(indicators_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        items = []
        for entry in payload.get("items", []):
            severity = entry.get("severity") or entry.get("priority") or "N/A"
            kind = entry.get("kind") or entry.get("category") or "N/A"
            tags = entry.get("tags") or []
            category = kind
            if category == "N/A" and tags:
                category = tags[0]
            title = entry.get("title") or ""
            value = entry.get("value") or ""
            evidence_list = entry.get("evidence") or []
            evidence = evidence_list[0] if evidence_list else {}
            location = evidence.get("locator") or ""
            evidence_path = evidence.get("path") or ""
            items.append(
                {
                    "severity": severity,
                    "category": category,
                    "kind": kind,
                    "title": title,
                    "location": location,
                    "evidence": evidence_path,
                    "value": value,
                }
            )
        return items

    def _apply_findings_filters(self) -> None:
        if not self.severity_filter or not self.category_filter or not self.findings_search:
            return
        if not self.findings_table:
            return
        severity = self.severity_filter.currentText()
        query = self.findings_search.text().lower().strip()

        categories = sorted({item["category"] for item in self.findings})
        current_category = self.category_filter.currentText()
        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItems(["All", *categories])
        if current_category in categories:
            self.category_filter.setCurrentText(current_category)
        self.category_filter.blockSignals(False)
        category = self.category_filter.currentText()

        filtered = []
        for item in self.findings:
            if severity != "All" and item["severity"] != severity:
                continue
            if category != "All" and item["category"] != category:
                continue
            if query:
                haystack = " ".join(
                    [item["category"], item["title"], item["location"], item["evidence"]]
                ).lower()
                if query not in haystack:
                    continue
            filtered.append(item)

        self._populate_findings_table(filtered)

    def _apply_stage3_findings_filters(self) -> None:
        if not self.stage3_severity_filter or not self.stage3_category_filter or not self.stage3_findings_search:
            return
        severity = self.stage3_severity_filter.currentText()
        query = self.stage3_findings_search.text().lower().strip()

        categories = sorted({item["category"] for item in self.stage3_findings if item["category"] != "N/A"})
        current_category = self.stage3_category_filter.currentText()
        self.stage3_category_filter.blockSignals(True)
        self.stage3_category_filter.clear()
        self.stage3_category_filter.addItems(["All", *categories])
        if current_category in categories:
            self.stage3_category_filter.setCurrentText(current_category)
        self.stage3_category_filter.blockSignals(False)
        category = self.stage3_category_filter.currentText()

        severities = sorted({item["severity"] for item in self.stage3_findings if item["severity"] != "N/A"})
        current_severity = self.stage3_severity_filter.currentText()
        self.stage3_severity_filter.blockSignals(True)
        self.stage3_severity_filter.clear()
        self.stage3_severity_filter.addItems(["All", *severities])
        if current_severity in severities:
            self.stage3_severity_filter.setCurrentText(current_severity)
        self.stage3_severity_filter.blockSignals(False)
        severity = self.stage3_severity_filter.currentText()

        filtered = []
        for item in self.stage3_findings:
            if severity != "All" and item["severity"] != "N/A" and item["severity"] != severity:
                continue
            if category != "All" and item["category"] != category:
                continue
            if query:
                haystack = " ".join(
                    [item["title"], item["value"], item["evidence"]]
                ).lower()
                if query not in haystack:
                    continue
            filtered.append(item)

        self._populate_stage3_findings_table(filtered)

    def _populate_findings_table(self, rows: list[dict]) -> None:
        if not self.findings_table:
            return
        self.findings_table.setRowCount(0)
        for item in rows:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            self.findings_table.setItem(row, 0, QTableWidgetItem(item["severity"]))
            self.findings_table.setItem(row, 1, QTableWidgetItem(item["category"]))
            self.findings_table.setItem(row, 2, QTableWidgetItem(item["title"]))
            self.findings_table.setItem(row, 3, QTableWidgetItem(item["location"]))
            evidence_item = QTableWidgetItem(item["evidence"])
            evidence_item.setToolTip(item["evidence"])
            self.findings_table.setItem(row, 4, evidence_item)
            self.findings_table.item(row, 0).setData(Qt.UserRole, item)

    def _populate_stage3_findings_table(self, rows: list[dict]) -> None:
        if not self.stage3_findings_table:
            return
        self.stage3_findings_table.setRowCount(0)
        for item in rows:
            row = self.stage3_findings_table.rowCount()
            self.stage3_findings_table.insertRow(row)
            self.stage3_findings_table.setItem(row, 0, QTableWidgetItem(item["severity"]))
            self.stage3_findings_table.setItem(row, 1, QTableWidgetItem(item["category"]))
            self.stage3_findings_table.setItem(row, 2, QTableWidgetItem(item["title"]))
            self.stage3_findings_table.setItem(row, 3, QTableWidgetItem(item["location"]))
            evidence_item = QTableWidgetItem(item["evidence"])
            evidence_item.setToolTip(item["evidence"])
            self.stage3_findings_table.setItem(row, 4, evidence_item)
            self.stage3_findings_table.item(row, 0).setData(Qt.UserRole, item)

    def _open_finding_source(self, item: QTableWidgetItem) -> None:
        payload = self.findings_table.item(item.row(), 0).data(Qt.UserRole)
        if not payload or not self.current_run_dir:
            return
        rel_path = payload.get("file_path")
        if not rel_path:
            return
        abs_path = self.current_run_dir / rel_path
        if abs_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(abs_path)))
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.current_run_dir)))

    def _open_stage3_finding_source(self, item: QTableWidgetItem) -> None:
        if not self.stage3_run_dir or not self.stage3_findings_table:
            return
        payload = self.stage3_findings_table.item(item.row(), 0).data(Qt.UserRole)
        if not payload:
            return
        rel_path = payload.get("evidence")
        if not rel_path:
            return
        abs_path = self.stage3_run_dir / rel_path
        if abs_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(abs_path)))
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.stage3_run_dir)))

    def _load_logs(self, log_paths: list[Path] | None = None) -> None:
        self.log_paths.clear()
        if not self.log_view:
            return

        if log_paths is None:
            log_paths = []
            if self.current_run_dir:
                logs_dir = self.current_run_dir / "logs"
                if logs_dir.exists():
                    log_paths = sorted(logs_dir.glob("*.txt"))
                    runner_log = logs_dir / "runner.log"
                    if runner_log.exists():
                        log_paths.insert(0, runner_log)

        for path in log_paths:
            name = path.name
            self.log_paths[name] = path

        if self.log_combo:
            prev = self.log_combo.currentText()
            self.log_combo.blockSignals(True)
            self.log_combo.clear()
            for name in self.log_paths:
                self.log_combo.addItem(name)
            if prev and prev in self.log_paths:
                self.log_combo.setCurrentText(prev)
            elif "runner.log" in self.log_paths:
                self.log_combo.setCurrentText("runner.log")
            self.log_combo.blockSignals(False)

        self._render_log_view()

    def _ensure_live_logs(self, run_dir: Path) -> None:
        if not run_dir:
            return
        if self.current_run_dir != run_dir:
            self.current_run_dir = run_dir
            self._load_logs()
        elif not self.log_paths:
            self._load_logs()

    def _tick_analysis_timer(self) -> None:
        if not self.analysis_running or self._analysis_start_ts is None:
            return
        elapsed = time.monotonic() - self._analysis_start_ts
        self.progress_label.setText(
            f"{self._analysis_message} · {self._analysis_step_text} · "
            f"Elapsed {self._format_duration(elapsed)}"
        )
        if self.log_paths:
            self._render_log_view()

    def _render_log_view(self) -> None:
        if not self.log_view:
            return
        if not self.log_paths:
            self.log_view.setPlainText("")
            return
        # Pick selected log file from combo, fall back to runner.log or first available
        path = None
        if self.log_combo:
            path = self.log_paths.get(self.log_combo.currentText())
        if not path:
            path = self.log_paths.get("runner.log")
        if not path:
            path = next(iter(self.log_paths.values()), None)
        if not path or not path.exists():
            self.log_view.setPlainText("")
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            content = ""
        # Apply search filter
        query = self.log_search.text().strip() if self.log_search else ""
        if query:
            lines = [line for line in content.splitlines() if query.lower() in line.lower()]
            content = "\n".join(lines)
        self.log_view.setPlainText(content)
        autoscroll = self.log_autoscroll.isChecked() if self.log_autoscroll else True
        if autoscroll:
            self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def _load_stage3_logs(self, log_entries: list[tuple[str, Path]] | None = None) -> None:
        if not self.stage3_log_combo:
            return
        self.stage3_log_paths.clear()
        self.stage3_log_combo.blockSignals(True)
        self.stage3_log_combo.clear()

        if log_entries is None:
            log_entries = []
            if self.stage3_run_dir:
                tools_dir = self.stage3_run_dir / "tools"
                if tools_dir.exists():
                    tool_dirs = sorted([path for path in tools_dir.iterdir() if path.is_dir()])
                    for tool_dir in tool_dirs:
                        for label, filename in (("cmd", "cmd.txt"), ("stdout", "stdout.txt"), ("stderr", "stderr.txt")):
                            path = tool_dir / filename
                            if path.exists():
                                name = f"{tool_dir.name}: {label}"
                                log_entries.append((name, path))

        for name, path in log_entries:
            self.stage3_log_combo.addItem(name)
            self.stage3_log_paths[name] = path

        self.stage3_log_combo.blockSignals(False)
        if self.stage3_log_paths:
            preferred = None
            for name in self.stage3_log_paths:
                if name.startswith("quark: stdout"):
                    preferred = name
                    break
            if preferred is None:
                for name in self.stage3_log_paths:
                    if name.endswith("stdout"):
                        preferred = name
                        break
            if preferred:
                self.stage3_log_combo.setCurrentText(preferred)
        self._render_stage3_log_view()

    def _render_stage3_log_view(self) -> None:
        if not self.stage3_log_paths or not self.stage3_log_combo or not self.stage3_log_view:
            if self.stage3_log_view:
                self.stage3_log_view.setPlainText("")
            return
        current_name = self.stage3_log_combo.currentText()
        path = self.stage3_log_paths.get(current_name)
        if not path or not path.exists():
            self.stage3_log_view.setPlainText("")
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            content = ""
        query = self.stage3_log_search.text().lower().strip() if self.stage3_log_search else ""
        if query:
            filtered_lines = [line for line in content.splitlines() if query in line.lower()]
            content = "\n".join(filtered_lines)
        self.stage3_log_view.setPlainText(content)
        if self.stage3_log_autoscroll and self.stage3_log_autoscroll.isChecked():
            self.stage3_log_view.verticalScrollBar().setValue(
                self.stage3_log_view.verticalScrollBar().maximum()
            )

    def _render_apkleaks_log_view(self) -> None:
        if not self.apkleaks_log_view:
            return
        if not self.stage3_run_dir:
            self.apkleaks_log_view.setPlainText("")
            return
        path = self.stage3_run_dir / "tools" / "apkleaks" / "stdout.txt"
        if not path.exists():
            self.apkleaks_log_view.setPlainText("")
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            content = ""
        self.apkleaks_log_view.setPlainText(content)

    def _render_apkid_log_view(self) -> None:
        if not self.apkid_log_view:
            return
        if not self.stage3_run_dir:
            self.apkid_log_view.setPlainText("")
            return
        path = self.stage3_run_dir / "tools" / "apkid" / "stdout.txt"
        if not path.exists():
            self.apkid_log_view.setPlainText("")
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            content = ""
        self.apkid_log_view.setPlainText(content)

    def _open_stage3_tool_dir(
        self,
        tool_name: str | None,
        log_cb: Callable[[str], None] | None = None,
    ) -> None:
        run_dir = self.stage3_run_dir
        if not run_dir and self.current_stage_id == STAGE_CROSS_TOOL:
            run_dir = self.current_run_dir
        if not run_dir:
            if log_cb:
                log_cb("Stage3 run directory is not available yet.")
            return
        tools_root = run_dir / "tools"
        target = tools_root if tools_root.exists() else run_dir
        if tool_name:
            tool_dir = tools_root / tool_name
            target = tool_dir if tool_dir.exists() else target
            run_json = run_dir / "run.json"
            if run_json.exists():
                try:
                    data = json.loads(run_json.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError, ValueError):
                    data = {}
                tools = data.get("tools") or []
                for entry in tools:
                    if entry.get("tool") == tool_name and entry.get("tool_result"):
                        tool_result_path = run_dir / entry["tool_result"]
                        if tool_result_path.exists():
                            target = tool_result_path.parent
                        break
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))

    def _open_apkid_report_stub(self) -> None:
        if not self._stage3_tool_ok("apkid"):
            QMessageBox.information(
                self,
                "APKiD report",
                "APKiD report is available only after successful analysis.",
            )
            return
        self._open_stage3_report()

    def _open_apkleaks_report_stub(self) -> None:
        if not self._stage3_tool_ok("apkleaks"):
            QMessageBox.information(
                self,
                "APKLeaks report",
                "APKLeaks report is available only after successful analysis.",
            )
            return
        self._open_stage3_report()

    def _copy_stage3_log(self) -> None:
        if not self.stage3_log_view:
            return
        self.stage3_log_view.selectAll()
        self.stage3_log_view.copy()

    def _save_stage3_log(self) -> None:
        if not self.stage3_log_view:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save log", "", "Text files (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(self.stage3_log_view.toPlainText(), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def _open_stage3_log_file(self) -> None:
        if not self.stage3_log_combo:
            return
        current_name = self.stage3_log_combo.currentText()
        path = self.stage3_log_paths.get(current_name)
        if path and path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _copy_log(self) -> None:
        if not self.log_view:
            return
        self.log_view.selectAll()
        self.log_view.copy()

    def _save_log(self) -> None:
        if not self.log_view:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save log", "", "Text files (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(self.log_view.toPlainText(), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def _open_log_file(self) -> None:
        if self.log_combo:
            current_name = self.log_combo.currentText()
            path = self.log_paths.get(current_name)
        else:
            path = self.log_paths.get("runner.log")
            if not path:
                path = next(iter(self.log_paths.values()), None)
        if path and path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _load_artifacts(self, artifact_paths: list[Path] | None = None) -> None:
        if not self.artifacts_table:
            return
        self.artifacts_table.setRowCount(0)
        self.artifact_paths = []
        if artifact_paths is None:
            artifact_paths = []
            if self.current_run_dir:
                artifacts_dir = self.current_run_dir / "artifacts"
                if artifacts_dir.exists():
                    artifact_paths = [p for p in artifacts_dir.rglob("*") if p.is_file()]
        for path in artifact_paths:
            self._add_artifact_row(path)

    def _add_artifact_row(self, path: Path) -> None:
        row = self.artifacts_table.rowCount()
        self.artifacts_table.insertRow(row)
        size = self._format_size(path.stat().st_size)
        rel_path = str(path)
        if self.current_run_dir:
            try:
                rel_path = str(path.relative_to(self.current_run_dir))
            except ValueError:
                rel_path = str(path)
        self.artifacts_table.setItem(row, 0, QTableWidgetItem(path.name))
        self.artifacts_table.setItem(row, 1, QTableWidgetItem(rel_path))
        self.artifacts_table.setItem(row, 2, QTableWidgetItem(size))
        self.artifacts_table.item(row, 0).setData(Qt.UserRole, path)

    def _open_artifact(self) -> None:
        selected = self.artifacts_table.selectedItems()
        if not selected:
            return
        path = self.artifacts_table.item(selected[0].row(), 0).data(Qt.UserRole)
        if path and Path(path).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _reveal_artifact(self) -> None:
        selected = self.artifacts_table.selectedItems()
        if not selected:
            return
        path = self.artifacts_table.item(selected[0].row(), 0).data(Qt.UserRole)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).parent)))

    def _load_stage3_artifacts(self, artifact_paths: list[Path] | None = None) -> None:
        if not self.stage3_artifacts_table:
            return
        self.stage3_artifacts_table.setRowCount(0)
        if artifact_paths is None:
            artifact_paths = []
            if self.stage3_run_dir:
                run_json = self.stage3_run_dir / "run.json"
                if run_json.exists():
                    artifact_paths.append(run_json)
                indicators = self.stage3_run_dir / "normalized" / "indicators.json"
                if indicators.exists():
                    artifact_paths.append(indicators)
                tools_dir = self.stage3_run_dir / "tools"
                if tools_dir.exists():
                    for tool_dir in sorted([path for path in tools_dir.iterdir() if path.is_dir()]):
                        for name in ("tool_result.json", "stdout.txt", "stderr.txt", "cmd.txt"):
                            path = tool_dir / name
                            if path.exists():
                                artifact_paths.append(path)
        for path in artifact_paths:
            self._add_stage3_artifact_row(path)

    def _add_stage3_artifact_row(self, path: Path) -> None:
        if not self.stage3_artifacts_table:
            return
        row = self.stage3_artifacts_table.rowCount()
        self.stage3_artifacts_table.insertRow(row)
        size = self._format_size(path.stat().st_size)
        rel_path = str(path)
        if self.stage3_run_dir:
            try:
                rel_path = str(path.relative_to(self.stage3_run_dir))
            except ValueError:
                rel_path = str(path)
        self.stage3_artifacts_table.setItem(row, 0, QTableWidgetItem(path.name))
        self.stage3_artifacts_table.setItem(row, 1, QTableWidgetItem(rel_path))
        self.stage3_artifacts_table.setItem(row, 2, QTableWidgetItem(size))
        self.stage3_artifacts_table.item(row, 0).setData(Qt.UserRole, path)

    def _open_stage3_artifact(self) -> None:
        if not self.stage3_artifacts_table:
            return
        selected = self.stage3_artifacts_table.selectedItems()
        if not selected:
            return
        path = self.stage3_artifacts_table.item(selected[0].row(), 0).data(Qt.UserRole)
        if path and Path(path).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _reveal_stage3_artifact(self) -> None:
        if not self.stage3_artifacts_table:
            return
        selected = self.stage3_artifacts_table.selectedItems()
        if not selected:
            return
        path = self.stage3_artifacts_table.item(selected[0].row(), 0).data(Qt.UserRole)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).parent)))

    def _stage3_tool_status(self, tool_name: str) -> str:
        tool_path = self._stage3_tool_result_path(tool_name)
        if not tool_path or not tool_path.exists():
            return "-"
        try:
            data = json.loads(tool_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return "-"
        ok = data.get("ok")
        exit_code = data.get("exit_code")
        if ok is True:
            status = "OK"
        elif ok is False:
            status = "FAIL"
        else:
            status = "-"
        if isinstance(exit_code, int):
            status = f"{status} ({exit_code})"
        return status

    def _stage3_tool_ok(self, tool_name: str) -> bool:
        tool_path = self._stage3_tool_result_path(tool_name)
        if not tool_path or not tool_path.exists():
            return False
        try:
            data = json.loads(tool_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False
        return data.get("ok") is True

    def _stage3_tool_result_path(self, tool_name: str) -> Path | None:
        if not self.stage3_run_dir:
            return None
        tools = None
        if self.stage3_run_data:
            tools = self.stage3_run_data.get("tools")
        if isinstance(tools, list):
            for entry in tools:
                if entry.get("tool") == tool_name:
                    relpath = entry.get("tool_result")
                    if relpath:
                        return self.stage3_run_dir / relpath
        fallback = self.stage3_run_dir / "tools" / tool_name / "tool_result.json"
        return fallback if fallback.exists() else None

    def _is_run_stale(self, run: Run) -> bool:
        if not self.current_project or not self.current_project.apk_meta:
            return False
        try:
            imported_at = datetime.fromisoformat(self.current_project.apk_meta.imported_at)
            started_at = datetime.fromisoformat(run.started_at)
        except (ValueError, TypeError):
            return False
        return started_at < imported_at

    def _result_status(self, tool: str, result: CommandResult) -> str:
        if result.status:
            return result.status
        if result.timed_out or result.error:
            return "fail"
        if tool == "jadx" and self._log_contains(result, self.JADX_PARTIAL_PATTERN):
            return "partial"
        allowed = {0, None}
        allowed.update(self.ALLOWED_NONZERO_RETURN.get(tool, set()))
        if result.return_code in allowed:
            return "success"
        return "fail"

    def _log_contains(self, result: CommandResult, pattern: re.Pattern) -> bool:
        for path_str in (result.stdout_path, result.stderr_path):
            try:
                path = Path(path_str)
                if not path.exists():
                    continue
                if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except (OSError, UnicodeError):
                continue
        return False

    def _set_elided_label(self, label: QLabel, text: str) -> None:
        self._elide_labels[label] = text
        label.setToolTip(text)
        self._apply_elide(label)

    def _apply_elide(self, label: QLabel) -> None:
        text = self._elide_labels.get(label)
        if text is None:
            return
        width = max(label.width(), 10)
        elided = label.fontMetrics().elidedText(text, Qt.ElideMiddle, width)
        label.setText(elided)

    def _refresh_elided_labels(self) -> None:
        for label in self._elide_labels:
            self._apply_elide(label)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._refresh_elided_labels()

    @staticmethod
    def _format_duration(seconds: int) -> str:
        minutes, secs = divmod(max(0, int(seconds)), 60)
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.0f} {unit}"
            size /= 1024
        return f"{size:.0f} TB"
