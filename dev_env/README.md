# OwnCA — Dev Environment

**Русский** | [English](README.en.md)

---

Docker-окружение для локальной разработки: образы собираются из исходников, код
панели монтируется внутрь контейнера для live-reload. Описание самого продукта —
в корневом [README](../README.md).

## Быстрый старт

```bash
cd dev_env
docker compose up -d --build
```

Панель доступна:

| Адрес | Что это |
|---|---|
| `https://127.0.0.1:8444` | через nginx (ГОСТ + RSA TLS) — проверка полного стека |
| `http://127.0.0.1:8001` | напрямую к Django — для отладки |

Логин по умолчанию: `admin` / `admin`. PostgreSQL на хост не публикуется —
только внутри сети `gh_ownca_devnet`.

При первом запуске автоматически создаётся БД `ownca`, генерируются ГОСТ + RSA
сертификаты для nginx, применяются миграции Django и создаётся admin.

## Состав

| Файл | Назначение |
|---|---|
| `docker-compose.yml` | Три сервиса: `gh_ownca_dev_postgresql`, `gh_ownca_dev_nginx`, `gh_ownca_dev_dashboard` |
| `build.sh` | Сборка образов с опциональным включением CryptoPro CSP |
| `init-db.sh` | Инициализация БД при первом старте PostgreSQL |
| `postgresql.conf`, `pg_hba.conf` | Конфигурация PostgreSQL |
| `dashboard/Dockerfile` | Образ Django + openssl/gost-engine (+ CryptoPro CSP, если подан дистрибутив) |
| `dashboard/entrypoint.sh` | Стартовая последовательность панели |
| `dashboard/vendor/` | Staging дистрибутива CryptoPro на время сборки (заполняется `build.sh`) |
| `nginx/Dockerfile`, `nginx/entrypoint.sh` | nginx с ГОСТ TLS и генерацией собственной PKI |
| `nginx/nginx.conf` | TLS-фронтенд, проксирование на `dashboard:8001` |
| `nginx/openssl-gost.cnf` | Конфигурация OpenSSL с включённым gost-engine |

Весь стек namespace'ится под `gh_ownca` (проект, контейнеры, сеть, тома), чтобы
не столкнуться с другим `dev_env/`-стеком на том же хосте: без явного `name:`
Compose взял бы имя проекта из каталога (`dev_env`), и два таких стека молча
делили бы одни и те же тома.

## Live-reload

Каталог `ownca_dashboard/` монтируется в `/opt/app`: Python-код, шаблоны и
статика подхватываются Django StatReloader без пересборки. Пересборка нужна
только при изменении `requirements.txt` или `Dockerfile`.

Исключение — C-мост `ownca_dashboard/capi/ownca_capi.c`: это компилируемый код,
он пересобирается вместе с образом. Приём для быстрой итерации — в
[capi/README.md](../ownca_dashboard/capi/README.md).

## Стартовые последовательности

`dashboard/entrypoint.sh` на каждом старте: `compilemessages` (правки переводов
подхватываются без ручной команды) → `collectstatic` → `migrate` →
`ensure_admin` → `cryptopro_setup` (без CryptoPro ничего не делает) → `runserver
$BIND_ADDRESS`.

`nginx/entrypoint.sh` при первом старте генерирует в том `certs` собственную
PKI — ГОСТ-CA и серверный сертификат (`gost2012_256`, paramset A) плюс
RSA-пару для обычных браузеров. Это PKI **самого nginx**, она никак не связана
с УЦ, которые выпускает OwnCA. При повторных запусках генерация пропускается,
если `ca.crt` уже в томе. Дополнительные SAN — через `CERT_EXTRA_SANS`, срок —
через `CERT_DAYS`.

## Где что лежит

| Путь в контейнере | Что там | Том |
|---|---|---|
| `/var/lib/ownca` | Сертификаты УЦ, выпущенные сертификаты, CSR, CRL, счётчики, маркеры криптопровайдера; закрытые ключи **openssl**-УЦ (PEM, `0600`) | `gh_ownca_data` |
| `/var/lib/ownca/crls` | Опубликованные CRL — отдельный bind-mount, чтобы отдавать их наружу | каталог `dev_env/crls/` |
| `/var/opt/cprocsp/keys` | Контейнеры CryptoPro с закрытыми ключами ГОСТ-УЦ и сертификатов | `gh_ownca_cryptopro_keys` |
| `/var/opt/cprocsp/dsrf` | Пулы гаммы ДСЧ (`db1/kis_1`, `db2/kis_1`) | `gh_ownca_cryptopro_gamma` |
| `/etc/nginx/certs` | Собственная PKI nginx | `gh_ownca_certs` |
| `/var/lib/postgresql/data` | Индекс метаданных | `gh_ownca_pg_data` |
| `/opt/cprocsp`, `/opt/ownca/bin/ownca_capi` | Дистрибутив CryptoPro и мост к CAPILite | в образе |

Гамма вынесена в отдельный том сознательно: она расходуется (36 байт на
генерацию ключа) и должна переживать перезапуск, иначе после каждого перезапуска
генерация ключей падала бы до повторной загрузки гаммы.

> **Резервное копирование.** У CryptoPro-УЦ закрытый ключ лежит **не** в
> `/var/lib/ownca`, а в контейнере под `/var/opt/cprocsp/keys`. Резервная копия
> только каталога хранилища сохранит сертификаты и индекс, но не ключи —
> восстановленный УЦ не сможет ничего подписать. Резервировать нужно оба тома,
> и согласованно.

## Переменные окружения

Задаются в `dev_env/.env` — docker compose подхватывает его автоматически.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Логин администратора |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `DB_HOST` | `gh_ownca_dev_postgresql` | Хост PostgreSQL |
| `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `5432` / `ownca` / `ownca` / `ownca` | Параметры БД |
| `DJANGO_DEBUG` | `True` | Режим Django |
| `DJANGO_ALLOWED_HOSTS` | `*` | Разрешённые хосты |
| `CSRF_TRUSTED_ORIGINS` | список из compose | Origin'ы для CSRF |
| `DJANGO_SECURE_COOKIES` | `False` в dev-стеке (в приложении — `True`) | Флаг `Secure` на cookie сессии; в dev выключен ради доступа по `http://…:8001` |
| `DJANGO_SECRET_KEY` | небезопасный dev-ключ | Ключ подписи Django |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Заголовок в верхней панели |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Каталог хранения УЦ и сертификатов |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Алгоритм ключей по умолчанию |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Срок действия УЦ по умолчанию (дней) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Срок действия сертификата по умолчанию (дней) |
| `OWNCA_CRL_DISTRIBUTION` | — | Публичный URL раздачи CRL (информационно) |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Включить криптопровайдер CryptoPro на запуске (действует, только если он запечён в образ) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Серийный номер лицензии (пусто → демонстрационная на 90 дней; значение из панели приоритетнее) |
| `OWNCA_CRYPTOPRO_GAMMA_DIR` | `/var/opt/cprocsp/dsrf` | Каталог гаммы ДСЧ |
| `OWNCA_CRYPTOPRO_ROOT` | `/opt/cprocsp` | Корень установки CryptoPro |
| `OWNCA_CRYPTOPRO_SHIM_BIN` | `/opt/ownca/bin/ownca_capi` | Мост к CAPILite |
| `OWNCA_CRYPTOPRO_MARKER` | `/opt/ownca/.cryptopro_available` | Маркер сборки с CryptoPro |
| `UPLOAD_MAX_MB` | `10` | Предельный размер загружаемого файла |
| `BIND_ADDRESS` | `0.0.0.0:8001` | Адрес runserver внутри контейнера |

Время сборки (`build.sh`, не контейнера):

| Переменная | По умолчанию | Описание |
|---|---|---|
| `OWNCA_CRYPTOPRO_DIST` | `dev_env/cryptopro_linux-amd64_deb.tgz` | Путь к дистрибутиву CryptoPro (`.tgz` с `.deb`); `none` — принудительно без CryptoPro |

Для nginx-контейнера: `CERT_DAYS` (по умолчанию `365`) и `CERT_EXTRA_SANS`
(формат `DNS:foo,IP:1.2.3.4`).

## Типовые операции

Все команды выполняются внутри контейнеров, чтобы не трогать хост.

```bash
D='docker compose -f dev_env/docker-compose.yml exec'

# тесты (нужна привилегия CREATEDB — один раз, см. ниже)
$D gh_ownca_dev_dashboard python manage.py test dashboard -v2

# shell и management-команды
$D gh_ownca_dev_dashboard python manage.py shell
$D gh_ownca_dev_dashboard python manage.py makemigrations

# PostgreSQL
$D gh_ownca_dev_postgresql psql -U ownca -d ownca

# переводы: после правки строк в коде/шаблонах
$D gh_ownca_dev_dashboard python manage.py makemessages -l ru -l en

# логи
docker compose -f dev_env/docker-compose.yml logs -f gh_ownca_dev_dashboard
```

Django-тест-раннер создаёт отдельную БД на том же PostgreSQL, поэтому
пользователю нужна привилегия `CREATEDB` (один раз):

```bash
docker compose -f dev_env/docker-compose.yml exec gh_ownca_dev_postgresql \
    psql -U postgres -c "ALTER USER ownca CREATEDB;"
```

Полученные `.po` переводятся вручную; `compilemessages` запускается на каждом
старте контейнера, отдельный шаг не нужен.

**Webhelp.** Контент справки лежит в
`ownca_dashboard/dashboard/webhelp/content/{ru,en}/*.md` и рендерится на лету,
но рендер обёрнут в `lru_cache` — правки `.md` reloader **не** подхватывает,
нужен `docker compose … restart gh_ownca_dev_dashboard`. Изменения в
`webhelp/nav.py` и прочих `.py` подхватываются как обычно.

## Сброс окружения

```bash
docker compose -f dev_env/docker-compose.yml down      # остановка, данные целы
docker compose -f dev_env/docker-compose.yml down -v   # полная очистка
```

> `down -v` уносит и контейнеры ключей CryptoPro вместе с гаммой — ключи всех
> CryptoPro-УЦ будут потеряны безвозвратно.

## Криптопровайдер CryptoPro CSP (опционально)

Дистрибутив CryptoPro (`.tgz` с `.deb`-пакетами) в репозиторий не входит.
Включение двухуровневое — сборка и запуск:

```bash
# положите cryptopro_linux-amd64_deb.tgz в dev_env/ и:
dev_env/build.sh
# либо укажите путь явно:
OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro_linux-amd64_deb.tgz dev_env/build.sh

# затем включите провайдера на запуске:
echo 'OWNCA_CRYPTOPRO_ENABLED=True' >> dev_env/.env
cd dev_env && docker compose up -d
```

`build.sh` копирует дистрибутив в `dashboard/vendor/cryptopro.tgz`, запускает
`docker compose build` и удаляет копию из контекста. Dockerfile ставит пакеты
(версия определяется из имени пакета в архиве), компилирует
`ownca_dashboard/capi/ownca_capi.c` → `/opt/ownca/bin/ownca_capi` и пишет
маркер `/opt/ownca/.cryptopro_available`. Нет дистрибутива — образ собирается
без CryptoPro, с явным сообщением; флаг `OWNCA_CRYPTOPRO_ENABLED` в таком
образе неактивен.

Управление провайдером — в панели обслуживания: состояние, лицензия, остаток
гаммы ДСЧ и её загрузка. Для генерации ключей на стенде без графического
интерфейса гамма обязательна: без неё генерация падает с
`NTE_SILENT_CONTEXT (0x80090022)` — CSP пытается запросить энтропию диалогом, а
контекст открыт с `CRYPT_SILENT`.
Тестовую гамму можно сгенерировать там же — только для стенда.

Ограничения — в корневом
[README](../README.md#ограничения-криптопровайдера-cryptopro), внутреннее
устройство
моста — в [capi/README.md](../ownca_dashboard/capi/README.md).

## Архитектура стека

```
Браузер ──> gh_ownca_dev_nginx :8444 ──> gh_ownca_dev_dashboard :8001 ──> gh_ownca_dev_postgresql :5432
                  ^                       |                       (gh_ownca_devnet)
                  |                       |
            том: certs              том: ownca_data
            (ГОСТ + RSA TLS)        (УЦ, ключи, CRL)
```

Все сервисы изолированы в bridge-сети `gh_ownca_devnet`; на хост опубликованы
только `8444` и `8001`.
