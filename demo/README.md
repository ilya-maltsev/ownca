# OwnCA — Demo Environment

**Русский** | [English](README.en.md)

---

Готовое окружение для демонстрации. Все сервисы запускаются одной командой из предсобранных образов.

## Сценарии использования

1. **Локальная сборка и запуск** — собрать образы на текущей машине и поднять стек.
2. **Перенос на изолированный хост** — собрать образы один раз, упаковать вместе с deploy-файлами в один tar.gz, передать на сервер без интернета и развернуть.

Оба сценария обслуживает один скрипт — `build-images.sh`.

---

## 1. Локальная сборка и запуск

### Сборка образов

```bash
cd demo
bash build-images.sh            # = bash build-images.sh build
```

Что произойдёт:

- `docker pull postgres:16` — подтягивается официальный образ PostgreSQL.
- `docker build -t ownca-nginx:latest` — собирается nginx с поддержкой ГОСТ TLS (`dev_env/nginx/Dockerfile`).
- `docker build -t ownca-dashboard:latest` — собирается Django-приложение с openssl/gost-engine (`dev_env/dashboard/Dockerfile`).

Контекст сборки формируется по белому списку (`DASHBOARD_FILES`, `NGINX_FILES` в скрипте). Всё, что не перечислено явно (документация, `.git`, dev-инструменты, runtime-данные), в образ не попадает.

#### Сборка отдельных образов

```bash
bash build-images.sh build dashboard      # только ownca-dashboard
bash build-images.sh build nginx          # только ownca-nginx
bash build-images.sh build postgres       # только pull postgres:16
bash build-images.sh build dash nginx     # несколько одновременно
```

Короткие имена: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).

### Запуск

```bash
docker compose up -d
```

Первый запуск занимает ~30 секунд:

- **PostgreSQL**: инициализация БД, создание пользователя `ownca`.
- **Nginx**: генерация ГОСТ + RSA PKI (CA и серверные сертификаты) — entrypoint `dev_env/nginx/entrypoint.sh`.
- **Dashboard**: `compilemessages` + `collectstatic` + `migrate` + `ensure_admin` — entrypoint `dev_env/dashboard/entrypoint.sh`.

### Доступ

| URL | Описание |
|---|---|
| `https://localhost:9443` | Панель управления (через nginx, ГОСТ + RSA TLS) |

Логин: `admin` / `admin` (настраивается в `.env`).

---

## 2. Перенос на изолированный хост

### На машине-сборщике: экспорт

```bash
cd demo
bash build-images.sh all                  # build + export
# или раздельно:
bash build-images.sh build
bash build-images.sh export
```

Результат — единственный файл `demo/ownca-images.tar.gz`, содержащий:

- `docker-images.tar` — `docker save` для всех образов (`ownca-nginx`, `ownca-dashboard`, `postgres:16`).
- Deploy-файлы (`DEPLOY_PATHS` в скрипте): `build-images.sh`, `docker-compose.yml`, `init-db.sh`, `nginx.conf`, `README.md`.

В архив попадает только то, что нужно для деплоя — исходники, `.git`, dev-окружение остаются на сборщике.

#### Экспорт отдельных образов

```bash
bash build-images.sh export dashboard     # только ownca-dashboard + deploy-файлы
bash build-images.sh export nginx pg      # nginx + postgres + deploy-файлы
bash build-images.sh all dashboard        # build + export только dashboard
```

### На целевом хосте: импорт и запуск

```bash
# 1. Распаковать архив (например, в /opt)
tar xzf ownca-images.tar.gz -C /opt/
cd /opt/demo

# 2. Загрузить образы в локальный Docker
bash build-images.sh import
# или выборочно:
bash build-images.sh import dashboard

# 3. Поднять стек
docker compose up -d
```

`import` извлекает образы из `docker-images.tar` через `docker load` и удаляет временный tar после загрузки.

---

## Использование

После входа в панель:

1. **Создайте корневой удостоверяющий центр** на странице **Authorities**: укажите имя, Common Name, алгоритм (по умолчанию `gost2012_256`) и срок действия.
2. **Выпустите сертификат** на странице **Cert Issue**: выберите УЦ, профиль (server / client / code-signing / user), Common Name, Subject DN и SAN.
3. **Скачайте** сертификат, ключ и CSR со страницы деталей сертификата.
4. При необходимости **отзовите** сертификат — CRL будет автоматически перегенерирован.
5. **CRL** скачивается со страницы УЦ.

Все материалы (CA, ключи, выпущенные сертификаты, CRL) хранятся в volume `ownca_data` (`/var/lib/ownca` внутри контейнера).

## Настройка

Переменные окружения — в файле `.env`:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Логин администратора |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `OWNCA_PROJECT_NAME` | `OwnCA` | Короткое имя проекта |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Полное название в шапке |

## Состав

| Контейнер | Образ | Описание |
|---|---|---|
| `ownca-gh-demo-postgresql` | `postgres:16` | PostgreSQL на порту 5433 |
| `ownca-gh-demo-nginx` | `ownca-nginx:latest` | Nginx с ГОСТ + RSA TLS (порт 9443) |
| `ownca-gh-demo-dashboard` | `ownca-dashboard:latest` | Django на порту 9000 + openssl/gost-engine |

## Порты

| Порт | Сервис |
|---|---|
| `5433` | PostgreSQL |
| `9000` | Django (dashboard) |
| `9443` | nginx → dashboard (ГОСТ + RSA TLS) |

## Архитектура

```
Браузер ──────> nginx :9443 (ГОСТ + RSA TLS)
                       |
              Dashboard :9000
                  |--> openssl + gost-engine (генерация ключей и подпись)
                  |--> /var/lib/ownca  (CA, сертификаты, CRL на диске)
                  |--> PostgreSQL :5433  (индекс метаданных)
```

Все сервисы на `network_mode: host`.

## Остановка

```bash
docker compose down
```

Полная очистка (включая данные PostgreSQL, сертификаты nginx и материалы УЦ):

```bash
docker compose down -v
```

---

## Шпаргалка по `build-images.sh`

| Команда | Действие |
|---|---|
| `build-images.sh` | Собрать все образы (alias для `build`) |
| `build-images.sh build` | Собрать все образы |
| `build-images.sh build <name>...` | Собрать выбранные образы |
| `build-images.sh export` | Упаковать все образы + deploy-файлы в `ownca-images.tar.gz` |
| `build-images.sh export <name>...` | Упаковать выбранные образы + deploy-файлы |
| `build-images.sh import` | Загрузить все образы из `docker-images.tar` (требует распакованный архив) |
| `build-images.sh import <name>...` | Загрузить выбранные образы |
| `build-images.sh all` | `build` + `export` |
| `build-images.sh all <name>...` | `build` + `export` для выбранных образов |
| `build-images.sh help` | Справка |

Допустимые `<name>`: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).
