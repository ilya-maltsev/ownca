# OwnCA — Dev Environment

**Русский** | [English](README.en.md)

---

Docker-окружение для локальной разработки. Образы собираются из исходников, код панели монтируется внутрь контейнера для live-reload.

## Состав

| Файл | Назначение |
|---|---|
| `docker-compose.yml` | Описание трёх сервисов (PostgreSQL, ownca-gh-dev-nginx, ownca-gh-dev-dashboard) |
| `init-db.sh` | Инициализация БД при первом старте PostgreSQL (создание пользователя/схемы) |
| `postgresql.conf`, `pg_hba.conf` | Конфигурация PostgreSQL для dev-стека |
| `dashboard/Dockerfile` | Сборка образа Django + openssl/gost-engine |
| `dashboard/entrypoint.sh` | Стартовая последовательность панели (см. ниже) |
| `nginx/Dockerfile` | Сборка nginx с поддержкой ГОСТ TLS |
| `nginx/entrypoint.sh` | Генерация ГОСТ + RSA PKI для самого nginx |
| `nginx/nginx.conf` | TLS-фронтенд, проксирование на dashboard:8001 |
| `nginx/openssl-gost.cnf` | OpenSSL-конфигурация с включённым gost-engine |

## Быстрый старт

```bash
cd dev_env
docker compose up -d --build
```

Один `docker-compose.yml` поднимает все 3 сервиса. При первом запуске автоматически:
- создаётся БД `ownca`,
- генерируются ГОСТ + RSA сертификаты для nginx,
- применяются миграции Django,
- создаётся admin-пользователь.

Панель доступна:
- `https://127.0.0.1:8444` — через nginx (ГОСТ + RSA TLS, для проверки полного стека),
- `http://127.0.0.1:8001` — напрямую к Django (для отладки).

Логин по умолчанию: `admin` / `admin`.

## Live-reload

Каталог `ownca_dashboard/` монтируется в `/opt/app` контейнера — изменения в Python-коде, шаблонах и статике подхватываются Django StatReloader без пересборки. Пересборка нужна только при изменении `requirements.txt` или `Dockerfile`.

## Стартовая последовательность dashboard

Каждый раз при старте контейнера `dashboard/entrypoint.sh` выполняет:

1. `python manage.py compilemessages` — перекомпиляция `.po` → `.mo` (правки переводов подхватываются без ручной команды).
2. `python manage.py collectstatic --noinput` — обновление `staticfiles/`.
3. `python manage.py migrate --noinput` — применение миграций.
4. `python manage.py ensure_admin` — создание/обновление admin-пользователя из переменных окружения.
5. `exec python manage.py runserver $BIND_ADDRESS` — запуск dev-сервера с автоперезагрузкой.

## Стартовая последовательность nginx

`nginx/entrypoint.sh` при первом старте генерирует и сохраняет в volume `certs`:

| Сертификат | Назначение |
|---|---|
| `ca.crt` / `ca.key` | ГОСТ CA для nginx (внутренний, отдельный от того, что выпускает OwnCA) |
| `nginx.crt` / `nginx.key` | ГОСТ-сертификат TLS-сервера (`gost2012_256`, paramset A) |
| `ca-rsa.crt` / `ca-rsa.key` | RSA CA для nginx |
| `nginx-rsa.crt` / `nginx-rsa.key` | RSA-сертификат TLS-сервера для обычных браузеров |

При повторных запусках, если `ca.crt` уже есть в volume, генерация пропускается. Дополнительные SAN передаются через `CERT_EXTRA_SANS`, срок действия — через `CERT_DAYS`.

## Порты

| Порт | Сервис | Протокол |
|---|---|---|
| `8001` | Dashboard | HTTP (опубликован на хост — для отладки) |
| `8444` | nginx → dashboard | ГОСТ + RSA TLS |

PostgreSQL не публикуется на хост — доступ только из docker-сети `devnet`.

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Логин администратора |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `DB_HOST` | `ownca-gh-dev-postgresql` | Хост PostgreSQL |
| `DB_PORT` | `5432` | Порт PostgreSQL |
| `DB_NAME` | `ownca` | Имя БД |
| `DB_USER` | `ownca` | Пользователь БД |
| `DB_PASSWORD` | `ownca` | Пароль БД |
| `DJANGO_DEBUG` | `True` | Режим Django (в dev включён) |
| `DJANGO_ALLOWED_HOSTS` | `*` | Разрешённые хосты |
| `CSRF_TRUSTED_ORIGINS` | список из compose | Origin'ы для CSRF |
| `OWNCA_PROJECT_NAME` | `OwnCA` | Бренд в шапке/сайдбаре |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Длинный заголовок в topbar |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Каталог хранения CA и сертификатов |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Алгоритм ключей по умолчанию |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Срок действия CA по умолчанию (дней) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Срок действия сертификата по умолчанию (дней) |
| `OWNCA_CRL_DISTRIBUTION` | — | Публичный URL раздачи CRL (информационно) |
| `BIND_ADDRESS` | `0.0.0.0:8001` | Адрес/порт runserver внутри контейнера |

Для nginx-контейнера дополнительно:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `CERT_DAYS` | `365` | Срок действия сертификатов nginx |
| `CERT_EXTRA_SANS` | — | Дополнительные SAN (формат: `DNS:foo,IP:1.2.3.4`) |

## Типовые операции

Все команды выполняются внутри контейнера, чтобы не трогать хост.

### Тесты

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py test dashboard -v2
```

Django-тест-раннер создаёт отдельную БД на том же PostgreSQL, поэтому пользователю БД нужна привилегия `CREATEDB` (один раз):

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-postgresql \
    psql -U postgres -c "ALTER USER ownca CREATEDB;"
```

### Django shell / management-команды

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py shell
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py makemigrations
```

### PostgreSQL

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-postgresql \
    psql -U ownca -d ownca
```

### Переводы (i18n)

После правки строк в коде/шаблонах:

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py makemessages -l ru -l en
```

Полученные `.po`-файлы переводятся, после чего перезапуск контейнера (или ручной `compilemessages`) обновит `.mo`. Compile запускается автоматически на каждом старте — отдельный шаг не нужен.

### Webhelp (контекстная справка)

Контент справки лежит в `ownca_dashboard/dashboard/webhelp/content/{ru,en}/*.md` и рендерится на лету. Рендер обёрнут в `lru_cache`, поэтому правки `.md`-файлов **не подхватываются** автоматическим reloader'ом Django — нужен перезапуск контейнера:

```bash
docker compose -f dev_env/docker-compose.yml restart ownca-gh-dev-dashboard
```

Изменения в навигации (`webhelp/nav.py`) и в самих `.py`-модулях reloader подхватывает сам.

### Логи

```bash
docker compose -f dev_env/docker-compose.yml logs -f ownca-gh-dev-dashboard
docker compose -f dev_env/docker-compose.yml logs -f ownca-gh-dev-nginx
docker compose -f dev_env/docker-compose.yml logs -f ownca-gh-dev-postgresql
```

## Сброс окружения

Остановка с сохранением данных:

```bash
docker compose -f dev_env/docker-compose.yml down
```

Полная очистка (БД, сгенерированные сертификаты nginx, материалы УЦ):

```bash
docker compose -f dev_env/docker-compose.yml down -v
```

Volumes:
- `pg_data` — данные PostgreSQL,
- `certs` — ГОСТ/RSA сертификаты nginx,
- `ownca_data` — каталог `/var/lib/ownca` (CA, ключи, выпущенные сертификаты, CRL).

## Архитектура dev-стека

```
Браузер ──> ownca-gh-dev-nginx :8444 ──> ownca-gh-dev-dashboard :8001 ──> ownca-gh-dev-postgresql :5432
                  ^                       |                       (devnet)
                  |                       |
            volume: certs           volume: ownca_data
            (ГОСТ + RSA              (CA, ключи, CRL)
             TLS-фронтенд)
```

Все сервисы изолированы в bridge-сети `devnet`; на хост опубликованы только `8444` и `8001`.
