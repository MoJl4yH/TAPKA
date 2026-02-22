# TAPKA — Tools for APK Analysis

**TAPKA** — инструментальная система для автоматизированного анализа Android-приложений на предмет уязвимостей и недекларированных возможностей (НДВ). Реализует поэтапный подход: статический анализ (Stage1), корреляционный анализ сторонними инструментами (Stage3) с графическим интерфейсом, воспроизводимыми артефактами и структурированными отчётами.

---

## Зачем это нужно

Android-приложение может содержать уязвимости реализации (небезопасный TLS, hardcoded credentials, SQL injection) и недекларированные возможности (скрытый сбор данных, слежка, управление устройством) — всё это не всегда очевидно из документации. Ручная проверка каждого APK десятком инструментов занимает часы.

TAPKA решает эту задачу:

- **Автоматизирует** запуск цепочки инструментов — apktool, jadx, rg, yara, MobSF, Quark, APKiD, APKLeaks.
- **Фильтрует шум** — scope-based filtering исключает библиотечный код (gms, androidx, support) из статических находок, оставляя только код приложения.
- **Рассчитывает severity** — каждой находке присваивается severity (high/medium/low/info) на основе impact × confidence + контекстные бусты (persistence, network, combo).
- **Формирует отчёты** — HTML и JSON отчёты по каждому этапу с группировкой по severity и категориям.
- **Сохраняет артефакты** — логи, декомпилированный код, сертификаты, endpoints, per-tool JSON — всё воспроизводимо.

Результат — аналитик получает **приоритизированный список findings** для ручной проверки, а не сырой вывод десяти утилит.

---

## Быстрый старт

### 1. Установка окружения

```bash
git clone <repo_url> tapka
cd tapka
bash setup.sh
```

Скрипт автоматически:
- устанавливает системные пакеты (`apktool`, `jadx`, `yara`, `ripgrep`, `docker.io` и др.);
- создаёт Python venv `.venv/` и устанавливает зависимости из `requirements.txt`;
- клонирует правила Quark в `.tapka/quark-rules/`;
- проверяет Docker и опционально скачивает образ MobSF (~2.6 ГБ).

Доступные флаги:
```bash
bash setup.sh --skip-apt     # если системные пакеты уже установлены
bash setup.sh --skip-mobsf  # не скачивать Docker-образ MobSF
bash setup.sh --force-venv  # пересоздать .venv с нуля
```

### 2. Запуск

```bash
source .venv/bin/activate
python main.py
```

При первом запуске TAPKA предложит выбрать рабочую директорию. Внутри неё будет создана папка `tapka_workspace/projects/`. Путь сохраняется в `.tapka/settings.json`.

---

## Требования

### Системные инструменты (Stage1)

| Инструмент | Назначение | Установка |
|---|---|---|
| `java` / `keytool` | Запуск apktool, jadx; анализ сертификатов | `apt install default-jdk-headless` |
| `apktool` | Декомпиляция smali, извлечение ресурсов | `apt install apktool` |
| `jadx` | Декомпиляция DEX → Java | `apt install jadx` |
| `aapt2` | Парсинг APK manifest и метаданных | `apt install android-sdk-build-tools` |
| `apksigner` | Проверка подписи APK | `apt install android-sdk-build-tools` |
| `yara` | Сигнатурный скрининг | `apt install yara` |
| `rg` (ripgrep) | Паттерн-поиск по коду | `apt install ripgrep` |
| `strings`, `file`, `sha256sum`, `unzip` | Анализ бинарей и формата APK | обычно предустановлены |

### Системные инструменты (Stage3)

| Инструмент | Назначение | Установка |
|---|---|---|
| `docker` | Запуск MobSF-контейнера | `apt install docker.io` |

### Python-зависимости

```
PySide6==6.8.1          # GUI
pydantic==2.8.0         # модели данных
requests==2.32.3        # HTTP для MobSF API
quark-engine==26.1.1    # Quark Engine CLI
apkid==3.0.0            # APKiD CLI
apkleaks==2.6.3         # APKLeaks CLI
```

### Docker для MobSF

MobSF запускается как Docker-контейнер. Пользователь должен состоять в группе `docker`:

```bash
sudo usermod -aG docker $USER
newgrp docker          # применить без перелогина
docker ps              # проверить доступ
```

---

## Пользовательский сценарий

```
1. Новый проект       →  New Project → ввести название
2. Добавить APK       →  Add APK → выбрать .apk файл
3. Stage1 анализ      →  Run Analysis → ждать завершения (1–5 мин)
4. Открыть отчёт      →  Open Report → HTML с findings
5. Stage3 анализ      →  вкладка Stage3 → запустить MobSF / Quark / APKiD / APKLeaks
6. Просмотр итогов    →  отчёты и артефакты в папке run
```

**Несколько версий APK** — повторно нажать Add APK в том же проекте. Версии можно переключать в UI; каждая хранит свои runs независимо.

---

## Что делает Stage1

Stage1 — полностью автоматический статический анализ без запуска приложения.

### Шаги анализа

| Шаг | Инструмент | Что проверяет |
|---|---|---|
| Формат и хэш | `file`, `sha256sum` | Тип файла, SHA-256 для воспроизводимости |
| Подпись APK | `apksigner`, `keytool` | Схема подписи (V1/V2/V3), срок действия, отладочный сертификат |
| Manifest | `aapt2`, `apktool` | Разрешения, экспортируемые компоненты, `debuggable`, `allowBackup`, `minSdk`/`targetSdk` |
| Декомпиляция | `apktool`, `jadx` | Smali-байткод и Java-представление для поиска паттернов |
| Паттерн-поиск | `rg` (ripgrep) | 50+ категорий: endpoints, secrets, NDV-паттерны, security-issues, persistence, anomaly |
| Нативные библиотеки | `strings` + `rg` | Строки из `.so` файлов (endpoints, dynamic code, anti-analysis) |
| YARA | `yara` | Сигнатурный скрининг по `android_spy_triage.yar` |

### Scope filtering

Паттерн-поиск применяет **scope-based filtering** — паттерны ищут только в коде самого приложения, исключая сторонние библиотеки:

- `scope: "app"` — только пакет приложения (`com/example/myapp/`)
- `scope: "app_res"` — код приложения + ресурсы (`res/`, `assets/`)
- `scope: "full"` — весь APK (только для PEM-ключей и JWT)

Это снижает число ложных срабатываний на 90–97% на реальных APK.

### Категории findings

| Префикс | Описание |
|---|---|
| `ndv_*` | Недекларированные возможности: слежка, перехват трафика, удалённое управление |
| `sec_*` | Уязвимости реализации: TLS, WebView, SQL, хранение данных |
| `vul_*` | Уязвимости конфигурации: exported компоненты, backup, debuggable |
| `secret_*` | Секреты в коде: PEM-ключи, API-токены, credentials, JWT |
| `persist_*` | Механизмы персистентности: AlarmManager, WorkManager, JobScheduler |
| `anomaly_*` | Антианализ: детекция эмулятора, Frida/Xposed, обфускация |
| `supplychain_*` | Проблемы цепочки поставок: подпись, сертификат |

### Расчёт severity

```
score = (impact + tag_boost) × confidence_multiplier

  impact             — базовый вес категории (1–5)
  tag_boost          — контекст: +0.5 за каждый тег (network, persistence, exported, ...)
  confidence         — C3: ×1.0, C2: ×0.75, C1: ×0.5

  score ≥ 3.5  → high
  score ≥ 2.0  → medium
  score ≥ 1.0  → low
  score < 1.0  → info
```

Ряд категорий имеет `severity_floor` (гарантированный минимум): `vul_debuggable_true` → всегда **high**, `secret_private_key_pem` → **high** и т.д.

### Выходные артефакты Stage1

```
runs/<run_id>_stage1_static/
  run.json                        # мета-информация о запуске
  logs/                           # stdout/stderr каждого инструмента
  findings/findings.json          # все findings в JSON
  artifacts/
    out_apktool/                  # smali, ресурсы, manifest
    out_jadx/                     # декомпилированный Java-код
    certs/                        # сертификаты APK
    strings_so_scan.txt           # строки из .so файлов
    stage1_report.json            # машиночитаемый отчёт
    stage1_report.html            # HTML отчёт с фильтрами
    endpoints.urls.txt            # все найденные URL
    endpoints.ips.txt             # все найденные IP
```

---

## Что делает Stage3

Stage3 — корреляционный анализ с использованием специализированных инструментов. Каждый инструмент запускается независимо через отдельную вкладку UI.

### Инструменты

| Инструмент | Что анализирует |
|---|---|
| **MobSF** | Комплексный статический анализ: небезопасные конфигурации, опасные API, сетевая безопасность, трекеры. Запускается как Docker-контейнер. |
| **Quark Engine** | Поведенческий анализ по 250+ правилам: вредоносные паттерны, скрытое управление, нетипичные системные вызовы. Режим: monolith → при OOM автоматически переключается на per-rule fallback. |
| **APKiD** | Детекция упаковщиков, обфускаторов, антиотладочных механизмов (packer, obfuscator, anti-debug). |
| **APKLeaks** | Автоматизированный поиск утечек: API-ключи, токены, URL, конфигурационные параметры. |

### Нормализация

После каждого инструмента результаты нормализуются в единый формат `indicators.json`:

```
runs/<run_id>_stage3_cross_tool/
  tools/
    mobsf/       quark/       apkid/       apkleaks/
    # stdout.txt, stderr.txt, tool_result.json, артефакты
  normalized/
    indicators.json           # унифицированные индикаторы всех инструментов
  report/
    stage3_report.html        # сводный HTML отчёт Stage3
```

### Quark — режим запуска

Quark запускает все правила из `.tapka/quark-rules/rules/*.json`:

1. **Monolith** — `quark -r rules/ -a app.apk` (быстро, ~1–3 мин для малых APK).
2. **Per-rule fallback** — если монолит завершился с OOM (exit 137/SIGKILL), автоматически переключается: каждое правило запускается отдельным процессом с таймаутом 60 сек. Медленнее, но работает с любым APK.

---

## Структура проекта (файловая система)

```
tapka_workspace/
  projects/
    <project_id>/
      project.json
      versions/
        <version_id>/
          apk/original.apk
          meta.json
          runs/
            <run_id>_stage1_static/    ← Stage1 артефакты
            <run_id>_stage3_cross_tool/  ← Stage3 артефакты

.tapka/
  settings.json              ← workspace path
  quark-rules/               ← git clone quark-engine/quark-rules
    rules/*.json
```

---

## Ключевые модули

| Модуль | Назначение |
|---|---|
| `analysis/stage1_analysis.py` | Пайплайн Stage1: сбор findings, scope filtering, YARA, прогресс |
| `analysis/severity.py` | SeverityEngine: impact × confidence, tag boosts, severity floor |
| `analysis/reporting/` | Генерация HTML/JSON отчётов Stage1/Stage3 |
| `analysis/storage.py` | Файловая структура проектов/версий/ранов |
| `analysis/quark/runner.py` | QuarkRunner: monolith + OOM auto-fallback per-rule |
| `analysis/mobsf/` | MobSF Docker-клиент и Stage3 runner |
| `analysis/apkid/`, `analysis/apkleaks/` | APKiD и APKLeaks runners |
| `analysis/normalize/stage3.py` | Нормализация результатов Stage3 в indicators.json |
| `ui/main_window.py` | Главный GUI: проекты, Stage1, Stage3, отчёты |
| `models/` | Pydantic-модели: Run, Finding, QuarkReport, … |

---

## Развитие

### Overall report — сводный отчёт

Текущие Stage1 и Stage3 формируют отдельные отчёты. Следующий шаг — **единый сводный отчёт**, агрегирующий результаты всех этапов:

- Корреляция findings из Stage1 с индикаторами Stage3 (MobSF, Quark, APKLeaks).
- Устранение дублирования: одна и та же проблема, найденная разными инструментами, объединяется в один агрегированный finding с повышенной confidence.
- Итоговый вердикт по приложению с обоснованием и перечнем приоритетных областей для ручного анализа.

### Автоматизация Stage3

Сейчас каждый инструмент Stage3 запускается отдельно через UI. Планируется:

- Единый запуск «Stage3 Full» — последовательный прогон MobSF → Quark → APKiD → APKLeaks одной кнопкой.
- Автоматическая корреляция: после завершения всех инструментов генерируется единый Stage3-report с cross-tool findings.
- Настройка набора инструментов: возможность включить/отключить отдельные инструменты через конфигурацию.

### Расширение правил Stage3

- **Quark**: механизм добавления пользовательских правил без изменения кода — папка `~/.tapka/quark-rules/custom/`, автоматически включаемая в анализ.
- **YARA**: расширение `android_spy_triage.yar` — добавление семейств malware, spyware, stalkerware по актуальным сигнатурам.
- **APKLeaks**: кастомные regex-паттерны через конфигурационный файл для специфичных типов секретов (корпоративные токены, внутренние форматы конфигов).

### Stage2 — Динамический анализ

Stage2 реализует анализ **фактического поведения** приложения в изолированной среде. В отличие от Stage1, который анализирует код статически, Stage2 наблюдает за тем, что приложение делает при запуске.

Планируемый pipeline:

1. **Подготовка среды** — развёртывание Android-эмулятора (AOSP) на базе Android SDK; создание AVD (Android Virtual Device) с заданным API-уровнем; настройка перехвата трафика.

2. **Снимок до установки** — фиксация baseline-состояния файловой системы эмулятора и сетевых параметров (snapshot).

3. **Установка APK** — `adb install app.apk`; фиксация изменений файловой системы (diff baseline → post-install).

4. **Перехват трафика при установке** — `tcpdump` на сетевом интерфейсе эмулятора; фиксация DNS-запросов и сетевых соединений в момент первого запуска.

5. **Интерактивное тестирование** — ручное взаимодействие с UI приложения при продолжающемся захвате трафика; выявление сетевых соединений, активируемых действиями пользователя.

6. **Снимок после тестирования** — сравнение с baseline: новые файлы, изменённые настройки, созданные базы данных.

7. **Анализ результатов** — сопоставление наблюдаемых сетевых взаимодействий с endpoints из Stage1; верификация или опровержение гипотез, сформированных статическим анализом.

Инструменты Stage2: `adb`, `emulator` (Android SDK), `tcpdump`, `iptables`, `strace`, `diff`, `tar`.

### Единая формула оценки риска

Ключевая цель — **агрегированная оценка риска** APK на основе результатов всех трёх этапов. Планируется выработка взвешенной формулы:

```
RiskScore = w1 × S1_score + w2 × S2_score + w3 × S3_score

  S1_score  — взвешенная сумма severity findings Stage1
              (high: ×3, medium: ×2, low: ×1, с учётом категорий ndv/sec/vul)
  S2_score  — поведенческие индикаторы Stage2
              (подтверждённые сетевые соединения, динамическая загрузка кода,
               изменения ФС вне ожидаемых путей)
  S3_score  — кросс-инструментальный сигнал Stage3
              (MobSF security score + Quark matched rules ratio + APKiD flags)
  w1, w2, w3 — весовые коэффициенты (уточняются на тестовой выборке APK)
```

Итоговая оценка переводится в вердикт:

| RiskScore | Вердикт |
|---|---|
| < порога L | Признаки, требующие дополнительного анализа, не выявлены |
| ≥ порога L | Выявлены признаки, требующие дополнительного анализа |

Конкретные пороги и веса будут откалиброваны на размеченной выборке приложений.

### Уточнение severity findings

Текущая модель severity (`impact × confidence + tag_boost`) является эвристической. Планируется:

- **Привязка к CWE/OWASP Mobile Top 10** — каждая категория finding получает соответствующий CWE-идентификатор и OWASP Mobile Top 10 пункт. Это позволит использовать стандартизованные шкалы при формировании отчётов.

- **Контекстный severity** — один и тот же finding может иметь разный риск в зависимости от заявленного назначения приложения. Например, `ndv_mic_eavesdropping` в приложении для видеозвонков — ожидаемо; в калькуляторе — критично. Планируется механизм профилей: тип приложения влияет на итоговый severity.

- **Корреляционное повышение severity** — finding, подтверждённый несколькими инструментами (Stage1 + Quark + MobSF), должен автоматически получать более высокий confidence и, соответственно, severity.

- **Разделение ndv и sec** — более чёткая граница между НДВ (наличие функциональности, не декларированной разработчиком) и уязвимостями (слабости реализации, эксплуатируемые третьей стороной). Разные шкалы оценки для разных классов проблем.
