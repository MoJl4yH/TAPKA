import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
from ui.main_window import MainWindow
from analysis.storage import Storage
from analysis.settings import load_settings, save_settings, DEFAULT_WORKSPACE

def main():
    # Application initialization.
    app = QApplication(sys.argv)

    settings = load_settings()
    workspace = settings.get("workspace")
    if not workspace:
        default_path = os.path.expanduser(DEFAULT_WORKSPACE)
        default_dir = default_path if Path(default_path).exists() else str(Path.home())
        QMessageBox.information(
            None,
            "Настройка рабочей области",
            "Первый запуск: выберите родительский каталог.\n"
            "TAPKA создаст внутри него каталог 'tapka_workspace' (с подпапкой 'projects').\n"
            f"Предлагаемый путь по умолчанию: {default_path}",
        )
        chosen = QFileDialog.getExistingDirectory(
            None,
            "Выберите каталог рабочей области для проектов TAPKA",
            default_dir,
        )
        if not chosen:
            QMessageBox.warning(
                None,
                "Требуется рабочая область",
                "Рабочая область не выбрана. TAPKA будет закрыта.",
            )
            sys.exit(0)
        workspace_path = Path(chosen)
        if workspace_path.name != "tapka_workspace":
            workspace_path = workspace_path / "tapka_workspace"
        workspace_path.mkdir(parents=True, exist_ok=True)
        settings["workspace"] = str(workspace_path)
        save_settings(settings)
        workspace = str(workspace_path)

    # Create a Storage instance for project operations.
    storage = Storage(workspace=workspace)

    # Create the main window and pass storage.
    window = MainWindow(storage)

    # Show the window.
    window.show()

    # Start the event loop.
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
