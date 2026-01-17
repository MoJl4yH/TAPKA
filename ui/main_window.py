from __future__ import annotations

import json
import time
import traceback
from pathlib import Path
from datetime import datetime
import re
import xml.etree.ElementTree as ET

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
from analysis.stages import STAGES, STAGE_OVERALL, STAGE_STATIC
from analysis.stage1_analysis import Stage1StaticRunner
from analysis.reporting import ReportManager
from models import Project, Run, CommandResult
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
        self.progress_label: QLabel | None = None
        self.progress_bar: QProgressBar | None = None
        self.status_badge: QLabel | None = None
        self.metric_permissions: QLabel | None = None
        self.metric_exported: QLabel | None = None
        self.metric_endpoints: QLabel | None = None
        self.metric_secrets: QLabel | None = None
        self.metric_jadx: QLabel | None = None
        self.metric_updated: QLabel | None = None
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

        self.setWindowTitle("TAPKA — Tools for APK analysis")
        self.setMinimumSize(1100, 720)
        self.setObjectName("MainWindow")
        self._logo_path = Path(__file__).resolve().parent / "87288873-75ab-4871-bf62-f126ff451e6c.png"
        if self._logo_path.exists():
            self.setWindowIcon(QIcon(str(self._logo_path)))

        self._build_ui()
        self._apply_theme()
        self._setup_timers()
        self.refresh_projects()
        self._update_action_states()

    def _setup_timers(self) -> None:
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setInterval(1000)
        self._analysis_timer.timeout.connect(self._tick_analysis_timer)

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
            self._build_stub_stage_page(
                "Cross-tool analysis will be available in a future update.",
            ),
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
        stage1_layout.addWidget(self._build_actions_card())
        stage1_layout.addWidget(self._build_progress_card())
        stage1_layout.addWidget(self._build_checks_card())
        self.tabs = QTabWidget()
        self.tabs.setObjectName("innerTabs")
        self._build_overview_tab()
        self._build_findings_tab()
        self._build_logs_tab()
        self._build_artifacts_tab()
        stage1_layout.addWidget(self.tabs, stretch=1)
        return stage1_page

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

    def _build_actions_card(self) -> QFrame:
        actions_card = QFrame()
        actions_card.setObjectName("card")
        actions_layout = QHBoxLayout(actions_card)
        actions_layout.setContentsMargins(16, 12, 16, 12)
        actions_layout.setSpacing(10)

        self.add_apk_button = QPushButton("Add APK")
        self.add_apk_button.clicked.connect(self._add_apk)
        actions_layout.addWidget(self.add_apk_button)

        self.run_analysis_button = QPushButton("Run analysis")
        self.run_analysis_button.setObjectName("primaryButton")
        self.run_analysis_button.clicked.connect(self._run_analysis)
        actions_layout.addWidget(self.run_analysis_button)

        self.open_report_button = QPushButton("Open report")
        self.open_report_button.clicked.connect(self._open_report)
        actions_layout.addWidget(self.open_report_button)

        self.generate_report_button = QPushButton("Generate report")
        self.generate_report_button.clicked.connect(self._generate_report)
        actions_layout.addWidget(self.generate_report_button)

        actions_layout.addStretch()
        return actions_card

    def _build_progress_card(self) -> QFrame:
        progress_card = QFrame()
        progress_card.setObjectName("card")
        progress_layout = QHBoxLayout(progress_card)
        progress_layout.setContentsMargins(16, 10, 16, 10)

        self.progress_label = QLabel("Ready")
        self.progress_label.setObjectName("muted")
        progress_layout.addWidget(self.progress_label, stretch=1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar, stretch=2)
        return progress_card

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
            status_button.clicked.connect(lambda checked=False, tool=tool: self._open_tool_stderr(tool))
            status_layout.addRow(f"{label}:", status_button)
            self.tool_status_buttons[tool] = status_button
        checks_layout.addLayout(status_layout)
        return checks_card
    def _build_overview_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        metrics_grid = QGridLayout()
        metrics_grid.setHorizontalSpacing(12)
        metrics_grid.setVerticalSpacing(12)

        self.metric_permissions = self._add_metric_card(metrics_grid, 0, 0, "Permissions")
        self.metric_exported = self._add_metric_card(metrics_grid, 0, 1, "Exported components")
        self.metric_endpoints = self._add_metric_card(metrics_grid, 0, 2, "Endpoints")
        self.metric_secrets = self._add_metric_card(metrics_grid, 1, 0, "Secrets hits")
        self.metric_jadx = self._add_metric_card(metrics_grid, 1, 1, "Jadx status")
        self.metric_updated = self._add_metric_card(metrics_grid, 1, 2, "Last analysis")

        layout.addLayout(metrics_grid)
        layout.addStretch()
        self.tabs.addTab(tab, "Overview")

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
        latest = self.storage.get_latest_run(self.current_project.project_id, stage)
        if not latest:
            self.current_run = None
            self.current_run_dir = None
            self.project_run_label.setText("-")
            self.status_badge.setText("Idle")
            self._clear_run_views()
            return
        self.current_run, self.current_run_dir = latest
        if self._is_run_stale(self.current_run):
            self.current_run = None
            self.current_run_dir = None
            self.project_run_label.setText("-")
            self.status_badge.setText("Idle")
            self._clear_run_views()
            return
        self.status_badge.setText(self.current_run.status)
        self.project_run_label.setText(self.current_run.finished_at or self.current_run.started_at)
        self._load_run_views()
        self._update_tool_statuses(self.current_run)

    def _clear_run_views(self) -> None:
        self.findings = []
        self._update_overview_metrics()
        self._populate_findings_table([])
        self._load_logs([])
        self._load_artifacts([])
        self._update_tool_statuses(None)

    def _load_run_views(self) -> None:
        if not self.current_run or not self.current_run_dir:
            self._clear_run_views()
            return
        self.findings = self._load_findings()
        self._update_overview_metrics()
        self._apply_findings_filters()
        self._load_logs()
        self._load_artifacts()

    def _update_overview_metrics(self) -> None:
        permissions, exported = self._manifest_metrics()
        endpoints = sum(
            1
            for item in self.findings
            if item["category"] in ("secret_endpoints_hardcoded", "url")
        )
        secrets = sum(
            1
            for item in self.findings
            if (
                item["category"].startswith("secret_")
                and item["category"] != "secret_endpoints_hardcoded"
            )
            or item["category"] in ("sensitive_kv", "jwt")
        )
        jadx_status = self._tool_status("jadx")
        last_run = self.current_run.finished_at if self.current_run else "-"

        self.metric_permissions.setText(str(permissions) if permissions is not None else "-")
        self.metric_exported.setText(str(exported) if exported is not None else "-")
        self.metric_endpoints.setText(str(endpoints))
        self.metric_secrets.setText(str(secrets))
        self.metric_jadx.setText(jadx_status)
        self.metric_updated.setText(last_run or "-")

    def _manifest_metrics(self) -> tuple[int | None, int | None]:
        if not self.current_run_dir:
            return None, None
        manifest_path = self.current_run_dir / "artifacts" / "out_apktool" / "AndroidManifest.xml"
        if not manifest_path.exists():
            return None, None
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except (ET.ParseError, OSError):
            return None, None

        ns = "{http://schemas.android.com/apk/res/android}"
        permissions = set()
        for perm in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
            name = perm.get(f"{ns}name") or perm.get("name")
            if name:
                permissions.add(name)

        exported_count = 0
        application = root.find("application")
        if application is not None:
            for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                for component in application.findall(tag):
                    exported = component.get(f"{ns}exported")
                    if exported is not None:
                        is_exported = exported.lower() == "true"
                    else:
                        has_intent = component.find("intent-filter") is not None
                        is_exported = has_intent and tag in ("activity", "activity-alias", "service", "receiver")
                    if is_exported:
                        exported_count += 1

        return len(permissions), exported_count

    def _create_project(self, checked: bool = False) -> None:
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

    def _add_apk(self, checked: bool = False) -> None:
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
        self._update_action_states()

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
        self._load_logs([])
        self._focus_logs_tab()
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
            logs_index = None
            for index in range(self.tabs.count()):
                if self.tabs.tabText(index).lower() == "logs":
                    logs_index = index
                    break
            if logs_index is None and self.tabs.count() > 2:
                logs_index = 2
            if logs_index is not None:
                self.tabs.setCurrentIndex(logs_index)
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

    def _clear_selection(self) -> None:
        self.project_list.clearSelection()
        self._set_current_project(None)

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

    def _update_action_states(self) -> None:
        has_project = self.current_project is not None
        has_apk = has_project and self.current_project.apk_meta is not None
        has_run = self.current_run is not None
        running = self.analysis_running
        on_static_stage = self.current_stage_id == STAGE_STATIC

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

        self.log_copy_button.setEnabled(has_run)
        self.log_save_button.setEnabled(has_run)
        self.log_open_button.setEnabled(has_run)
        self.artifacts_open_button.setEnabled(has_run)
        self.artifacts_reveal_button.setEnabled(has_run)

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

    def _apply_findings_filters(self) -> None:
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

    def _populate_findings_table(self, rows: list[dict]) -> None:
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

    def _load_logs(self, log_paths: list[Path] | None = None) -> None:
        self.log_paths.clear()
        self.log_combo.blockSignals(True)
        self.log_combo.clear()

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
            self.log_combo.addItem(name)
            self.log_paths[name] = path

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
        if "runner.log" in self.log_paths:
            if self.log_combo.currentText() != "runner.log":
                self.log_combo.setCurrentText("runner.log")

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
        if not self.log_paths:
            self.log_view.setPlainText("")
            return
        current_name = self.log_combo.currentText()
        path = self.log_paths.get(current_name)
        if not path or not path.exists():
            self.log_view.setPlainText("")
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            content = ""
        query = self.log_search.text().lower().strip()
        if query:
            filtered_lines = [line for line in content.splitlines() if query in line.lower()]
            content = "\n".join(filtered_lines)
        self.log_view.setPlainText(content)
        if self.log_autoscroll.isChecked():
            self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def _copy_log(self) -> None:
        self.log_view.selectAll()
        self.log_view.copy()

    def _save_log(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save log", "", "Text files (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(self.log_view.toPlainText(), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def _open_log_file(self) -> None:
        current_name = self.log_combo.currentText()
        path = self.log_paths.get(current_name)
        if path and path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _load_artifacts(self, artifact_paths: list[Path] | None = None) -> None:
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

    def _tool_status(self, tool: str) -> str:
        if not self.current_run:
            return "-"
        results = [res for res in self.current_run.command_results if res.tool == tool]
        if not results:
            return "-"
        statuses = [self._result_status(tool, res) for res in results]
        if "fail" in statuses:
            return "FAIL"
        if "partial" in statuses:
            return "PARTIAL"
        if "success" in statuses:
            return "SUCCESS"
        return "-"

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
