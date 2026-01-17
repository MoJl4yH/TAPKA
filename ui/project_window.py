from pathlib import Path
import re
import time
import traceback

from PySide6.QtCore import QThread, Signal, Qt, QUrl, QTimer
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QHBoxLayout,
    QFormLayout,
    QMessageBox,
    QFrame,
    QProgressBar,
)

from analysis.stage1_analysis import Stage1StaticRunner
from analysis.reporting import ReportManager
from analysis.stages import STAGE_STATIC
from analysis.storage import Storage
from models import Project, Run, CommandResult
from ui.style import APP_STYLE


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


class ProjectWindow(QWidget):
    TOOL_STATUS_DEFS = [
        ("apksigner", "APK signature"),
        ("aapt2", "Manifest (aapt2)"),
        ("keytool", "Certificates"),
        ("apktool", "Resources (apktool)"),
        ("jadx", "Decompile (jadx)"),
        ("rg", "Pattern scan (rg)"),
        ("strings", "Native strings"),
        ("yara", "YARA scan"),
    ]
    ALLOWED_NONZERO_RETURN = {"rg": {1}}
    JADX_PARTIAL_PATTERN = re.compile(r"finished with errors", re.IGNORECASE)

    def __init__(self, storage: Storage, project: Project):
        super().__init__()
        self.storage = storage
        self.project = project
        self.current_run: Run | None = None
        self.current_run_dir = None
        self.worker: Stage1Worker | None = None
        self.tool_status_labels: dict[str, QPushButton] = {}
        self._analysis_timer: QTimer | None = None
        self._analysis_start_ts: float | None = None
        self._analysis_message = "Starting analysis"
        self._analysis_step_text = "0/0"
        self.title_label: QLabel | None = None
        self.subtitle_label: QLabel | None = None
        self.status_label: QLabel | None = None
        self.apk_name_label: QLabel | None = None
        self.sha_label: QLabel | None = None
        self.size_label: QLabel | None = None
        self.progress_label: QLabel | None = None
        self.progress_bar: QProgressBar | None = None
        self.run_button: QPushButton | None = None
        self.open_artifacts_button: QPushButton | None = None
        self.open_logs_button: QPushButton | None = None
        self.open_report_button: QPushButton | None = None

        self.setWindowTitle(f"Project: {project.project_id}")
        self.setMinimumSize(600, 320)
        self.setObjectName("ProjectWindow")
        self.setStyleSheet(APP_STYLE)
        self._setup_timers()

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        self._build_header(layout)
        self._build_details_card(layout)
        self._build_stage_card(layout)
        self._build_open_card(layout)
        self.setLayout(layout)

        self._load_latest_run()
        self._update_open_buttons()

    def _build_header(self, layout: QVBoxLayout) -> None:
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        self.title_label = QLabel("Project Overview")
        self.title_label.setObjectName("titleLabel")
        self.subtitle_label = QLabel(self.project.project_id)
        self.subtitle_label.setObjectName("subtitleLabel")
        title_box.addWidget(self.title_label)
        title_box.addWidget(self.subtitle_label)
        header_row.addLayout(title_box)

        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("statusBadge")
        header_row.addStretch()
        header_row.addWidget(self.status_label, alignment=Qt.AlignTop)
        layout.addLayout(header_row)

    def _build_details_card(self, layout: QVBoxLayout) -> None:
        details_card = QFrame()
        details_card.setObjectName("card")
        details_layout = QVBoxLayout(details_card)
        details_layout.setContentsMargins(16, 16, 16, 16)
        details_layout.setSpacing(10)

        details_header = QLabel("APK Info")
        details_header.setObjectName("sectionLabel")
        details_layout.addWidget(details_header)

        form = QFormLayout()
        self.apk_name_label = QLabel(self.project.apk_meta.name)
        self.sha_label = QLabel(self.project.apk_meta.sha256)
        self.size_label = QLabel(f"{self.project.apk_meta.size} bytes")
        form.addRow("APK Name:", self.apk_name_label)
        form.addRow("SHA256:", self.sha_label)
        form.addRow("Size:", self.size_label)
        details_layout.addLayout(form)
        layout.addWidget(details_card)

    def _build_stage_card(self, layout: QVBoxLayout) -> None:
        stage_card = QFrame()
        stage_card.setObjectName("card")
        stage_layout = QVBoxLayout(stage_card)
        stage_layout.setContentsMargins(16, 16, 16, 16)
        stage_layout.setSpacing(10)

        stage_header = QLabel("Stage 1 (Static)")
        stage_header.setObjectName("sectionLabel")
        stage_layout.addWidget(stage_header)

        stage_hint = QLabel("Runs local tools and stores logs, artifacts, and a report.")
        stage_hint.setObjectName("subtitleLabel")
        stage_hint.setWordWrap(True)
        stage_layout.addWidget(stage_hint)

        self.progress_label = QLabel("Waiting to start.")
        self.progress_label.setObjectName("subtitleLabel")
        stage_layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        stage_layout.addWidget(self.progress_bar)

        status_header = QLabel("Analysis status")
        status_header.setObjectName("sectionLabel")
        stage_layout.addWidget(status_header)

        status_layout = QFormLayout()
        for tool, label in self.TOOL_STATUS_DEFS:
            status_label = QPushButton("Not run")
            status_label.setObjectName("toolStatus")
            status_label.setProperty("status", "pending")
            status_label.setFlat(True)
            status_label.setCursor(Qt.ArrowCursor)
            status_label.clicked.connect(lambda checked=False, tool=tool: self._open_tool_stderr(tool))
            status_layout.addRow(f"{label}:", status_label)
            self.tool_status_labels[tool] = status_label
        stage_layout.addLayout(status_layout)

        stage_row = QHBoxLayout()
        self.run_button = QPushButton("Run Stage 1 (Static)")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self.run_stage1)
        stage_row.addWidget(self.run_button)
        stage_row.addStretch()
        stage_layout.addLayout(stage_row)
        layout.addWidget(stage_card)

    def _build_open_card(self, layout: QVBoxLayout) -> None:
        open_card = QFrame()
        open_card.setObjectName("card")
        open_layout = QVBoxLayout(open_card)
        open_layout.setContentsMargins(16, 16, 16, 16)
        open_layout.setSpacing(10)

        open_header = QLabel("Open Outputs")
        open_header.setObjectName("sectionLabel")
        open_layout.addWidget(open_header)

        button_row = QHBoxLayout()
        self.open_artifacts_button = QPushButton("Open artifacts")
        self.open_artifacts_button.clicked.connect(self.open_artifacts)
        button_row.addWidget(self.open_artifacts_button)

        self.open_logs_button = QPushButton("Open logs")
        self.open_logs_button.clicked.connect(self.open_logs)
        button_row.addWidget(self.open_logs_button)

        self.open_report_button = QPushButton("Open report")
        self.open_report_button.clicked.connect(self.open_report)
        button_row.addWidget(self.open_report_button)

        button_row.addStretch()
        open_layout.addLayout(button_row)
        layout.addWidget(open_card)

    def _setup_timers(self) -> None:
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setInterval(1000)
        self._analysis_timer.timeout.connect(self._tick_analysis_timer)

    def _load_latest_run(self) -> None:
        latest = self.storage.get_latest_run(self.project.project_id)
        if not latest:
            self.status_label.setText("Idle")
            return
        self.current_run, self.current_run_dir = latest
        self.status_label.setText(f"{self.current_run.status}")
        self._update_tool_statuses(self.current_run)

    def _update_open_buttons(self) -> None:
        has_run = self.current_run_dir is not None
        self.open_artifacts_button.setEnabled(has_run)
        self.open_logs_button.setEnabled(has_run)
        self.open_report_button.setEnabled(has_run)

    def run_stage1(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self._analysis_start_ts = time.monotonic()
        self._analysis_message = "Starting Stage 1..."
        self._analysis_step_text = "0/0"
        if self._analysis_timer:
            self._analysis_timer.start()
        self.status_label.setText("Running")
        self.progress_label.setText("Starting Stage 1...")
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self.run_button.setEnabled(False)
        self.open_artifacts_button.setEnabled(False)
        self.open_logs_button.setEnabled(False)
        self.open_report_button.setEnabled(False)
        self._update_tool_statuses(None, running=True)

        self.worker = Stage1Worker(self.storage, self.project.project_id)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_run_finished)
        self.worker.failed.connect(self._on_run_failed)
        self.worker.start()

    def _on_run_finished(self, run: Run) -> None:
        self.run_button.setEnabled(True)
        if self._analysis_timer:
            self._analysis_timer.stop()
        self._analysis_start_ts = None
        self.current_run = run
        self.current_run_dir = self.storage.get_run_dir(self.project.project_id, run.run_id)
        self.status_label.setText(f"{run.status}")
        self.progress_label.setText("Stage 1 completed.")
        self.progress_bar.setValue(self.progress_bar.maximum())
        self._update_open_buttons()
        self._update_tool_statuses(run)

    def _on_run_failed(self, message: str) -> None:
        self.run_button.setEnabled(True)
        if self._analysis_timer:
            self._analysis_timer.stop()
        self._analysis_start_ts = None
        self._load_latest_run()
        self._update_open_buttons()
        self.status_label.setText("Error")
        self.progress_label.setText("Stage 1 failed. Check logs.")
        self._update_tool_statuses(self.current_run)
        QMessageBox.warning(self, "Stage 1 Failed", message)

    def _on_progress(self, payload: dict) -> None:
        completed = int(payload.get("completed", 0))
        total = int(payload.get("total", 0)) or 1
        message = payload.get("message", "Running...")
        elapsed_sec = payload.get("elapsed_sec")

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

    def _tick_analysis_timer(self) -> None:
        if self._analysis_start_ts is None:
            return
        elapsed = time.monotonic() - self._analysis_start_ts
        self.progress_label.setText(
            f"{self._analysis_message} · {self._analysis_step_text} · "
            f"Elapsed {self._format_duration(elapsed)}"
        )

    def _set_tool_status(self, tool: str, status: str, text: str | None = None) -> None:
        label = self.tool_status_labels.get(tool)
        if not label:
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
        label.setText(text or text_map.get(status, status))
        label.setProperty("status", status)
        label.setCursor(Qt.PointingHandCursor if status == "fail" else Qt.ArrowCursor)
        label.style().unpolish(label)
        label.style().polish(label)

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
        label = self.tool_status_labels.get(tool)
        if not label or label.property("status") != "fail":
            return
        if not self.current_run_dir or not self.current_run:
            return
        results = [result for result in self.current_run.command_results if result.tool == tool]
        failing = [result for result in results if self._result_status(tool, result) == "fail"]
        if not failing:
            return
        stderr_path = Path(failing[0].stderr_path)
        if stderr_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(stderr_path)))
        else:
            logs_dir = self.current_run_dir / "logs"
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(logs_dir)))

    def _result_status(self, tool: str, result: CommandResult) -> str:
        if result.status:
            return result.status
        if result.timed_out or result.error:
            return "fail"
        if tool == "jadx" and self._is_jadx_partial(result):
            return "partial"
        allowed = {0, None}
        allowed.update(self.ALLOWED_NONZERO_RETURN.get(tool, set()))
        if result.return_code in allowed:
            return "success"
        return "fail"

    def _is_jadx_partial(self, result: CommandResult) -> bool:
        return self._log_contains(result, self.JADX_PARTIAL_PATTERN)

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

    @staticmethod
    def _format_duration(seconds: int) -> str:
        minutes, secs = divmod(max(0, int(seconds)), 60)
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def open_artifacts(self) -> None:
        if not self.current_run_dir:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.current_run_dir / "artifacts")))

    def open_logs(self) -> None:
        if not self.current_run_dir:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.current_run_dir / "logs")))

    def open_report(self) -> None:
        if not self.current_run_dir:
            return
        report_manager = ReportManager(self.storage)
        _, report_path = report_manager.report_paths(self.current_run_dir, STAGE_STATIC)
        if not report_path.exists():
            QMessageBox.information(self, "Report", "Report not found.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(report_path)))
