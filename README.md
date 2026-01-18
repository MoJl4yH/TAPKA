# TAPKA (Tools for APK analysis)

TAPKA - внутренний APK-анализатор с GUI для триажа Android приложений.
Фокус: быстрый Stage1 (Static analysis) с сохранением артефактов, логов и HTML/JSON отчета.

## Зачем проект
- Быстро собрать статические индикаторы (permissions, exported, endpoints, secrets, YARA).
- Сформировать воспроизводимый отчет для дальнейшего анализа и корреляции.
- Дать базу для Stage2 (динамика), Stage3 (внешние инструменты), Overall (сводный отчет).

## Быстрый запуск
1) Установить зависимости Python:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2) Запуск приложения:
```bash
python main.py
```

При первом запуске TAPKA попросит выбрать родительскую папку.
Внутри будет создан `tapka_workspace/` с подпапкой `projects/`.
Путь хранится в `.tapka/settings.json`.

## MobSF (Stage3) и доступ к Docker
MobSF запускается как Docker-контейнер. Для стабильной работы приложению нужен доступ к Docker daemon.
Рекомендуемый способ: дать пользователю доступ к сокету Docker через группу `docker`.

1) Добавить пользователя в группу `docker`:
```bash
sudo usermod -aG docker $USER
```

2) Перелогиниться (или обновить группы в текущей сессии):
```bash
newgrp docker
```

3) Проверить доступ:
```bash
docker ps
```

Если доступ к `docker.sock` запрещен, MobSF не сможет поднять контейнер и анализ Stage3 завершится с ошибкой.
Альтернатива: настроить rootless Docker, но это отдельная настройка окружения.

## Требования к внешним инструментам (Stage1)
Должны быть доступны в PATH:
- file, stat, sha256sum
- apksigner, aapt2, keytool
- unzip, grep
- apktool
- jadx
- rg (ripgrep)
- strings
- yara

## Основной пользовательский поток
1) New Project -> ввод имени проекта.
2) Add APK -> создается новая версия внутри проекта.
3) Run analysis -> выполняется Stage1.
4) Open report -> HTML отчет Stage1.

Добавление новой версии APK:
- повторно нажать Add APK в текущем проекте;
- в UI можно переключать активную версию.

## Где хранятся данные
Workspace (по умолчанию): `~/tapka_workspace`

Структура проекта:
```
tapka_workspace/
  projects/<project_id>/
    project.json
    versions/<version_id>/
      apk/original.apk
      meta.json
      runs/<run_id>/
        run.json
        logs/
          *.stdout.txt / *.stderr.txt
          runner.log
        findings/findings.json
        artifacts/
          out_apktool/
          out_jadx/
          certs/
          stage1_report.json
          stage1_report.html
          stage2_report.json/html (stub)
          stage3_report.json/html (stub)
          overall_report.json/html (stub)
          endpoints.urls.txt / endpoints.ips.txt / endpoints.*.json
```

## Что делает Stage1
Запускает набор локальных инструментов и формирует findings:
- apksigner, aapt2, apktool, jadx
- rg/strings (паттерны: endpoints, secrets, динамический код, антиотладка и пр.)
- yara (правила: android_spy_triage.yar)

После завершения:
- генерируется HTML + JSON отчет Stage1;
- создаются файлы endpoints.*;
- собираются логи по каждому инструменту.

## Отчеты
Stage1 отчет генерируется автоматически после анализа.
Кнопка "Generate report" активна только если отчета нет.

HTML отчет содержит:
- Summary (APK/Run/Findings)
- Tool status
- Extracted endpoints (Top N)
- Findings (с фильтрами, show more)
- Artifacts (с копированием абсолютного пути)

## Логи и прогресс
- В `runner.log` пишутся ключевые шаги Stage1.
- Во время анализа GUI показывает elapsed time, а лог обновляется в real-time.

## Внутренний контекст разработки
Ключевые модули:
- `analysis/stage1_analysis.py` - пайплайн Stage1, сбор findings, прогресс.
- `analysis/reporting.py` - генерация отчетов Stage1/Stage2/Stage3/Overall (Stage2/3/Overall пока заглушки).
- `analysis/severity.py` - расчет severity по impact x confidence + boosts.
- `analysis/storage.py` - структура проекта/версий/ранов, сохранение артефактов.
- `analysis/settings.py` - `.tapka/settings.json` (workspace).
- `analysis/stages.py` - список стадий и их названия.
- `ui/main_window.py` - основной GUI.
- `ui/project_window.py` - окно проекта.
- `models/*` - Pydantic-модели сущностей.

## Roadmap (планы развития)
Stage2 (Dynamic analysis):
- Запуск эмулятора AOSP.
- Загрузка APK, snapshot до установки.
- Сниффинг трафика при установке.
- Snapshot после установки, дифф между снимками.
- Запуск APK и сниффинг трафика во время ручного тестирования UI.
- Анализ результатов и добавление в отчет Stage2.

Stage3 (Cross-tool analysis):
- Запуск MobSF.
- Загрузка APK и анализ.
- Интерпретация результатов и включение в отчет Stage3.

Overall report:
- Интерпретация результатов Stage1-Stage3 с помощью open-source AI.
- Формирование финального отчета для application security expert.
