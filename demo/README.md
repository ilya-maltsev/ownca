# OwnCA — Demo Environment

**Русский** | [English](README.en.md)

---

Окружение для демонстрации: стек поднимается одной командой из предсобранных
образов. Описание самого продукта — в корневом [README](../README.md).

Два сценария, оба обслуживает скрипт `build-images.sh`:

1. **Локально** — собрать образы на этой машине и поднять стек.
2. **Перенос на изолированный хост** — собрать один раз, упаковать вместе с
   deploy-файлами в один `tar.gz`, передать на сервер без интернета и
   развернуть там.

## 1. Локальная сборка и запуск

```bash
cd demo
bash build-images.sh          # = build-images.sh build
docker compose up -d
```

Сборка подтягивает `postgres:16` и собирает два образа: `ownca-nginx:latest`
(nginx с ГОСТ TLS) и `ownca-dashboard:latest` (Django + openssl/gost-engine);
Dockerfile'ы берутся из `dev_env/`. Контекст сборки формируется по белому списку
(`DASHBOARD_FILES`, `NGINX_FILES` в скрипте) — документация, `.git`,
dev-инструменты и runtime-данные в образ не попадают.

Первый запуск занимает ~30 секунд: инициализация БД и пользователя `ownca`,
генерация ГОСТ + RSA PKI для nginx, затем `compilemessages` + `collectstatic` +
`migrate` + `ensure_admin` + `cryptopro_setup` (без CryptoPro ничего не делает).

Панель — на `https://localhost:9443`, логин `admin` / `admin`.

### Сборка отдельных образов

```bash
bash build-images.sh build dashboard      # только ownca-dashboard
bash build-images.sh build dash nginx     # несколько сразу
```

Короткие имена: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).

## 2. Перенос на изолированный хост

```bash
# на сборщике
cd demo
bash build-images.sh all                  # build + export

# на целевом хосте
tar xzf ownca-images.tar.gz -C /opt/
cd /opt/demo
bash build-images.sh import
docker compose up -d
```

`export` кладёт всё в единственный файл `demo/ownca-images.tar.gz`:
`docker-images.tar` (`docker save` всех образов) плюс deploy-файлы
(`DEPLOY_PATHS` в скрипте) — сам скрипт, `docker-compose.yml`, `.env.example`,
`init-db.sh`, `nginx.conf` и README. Исходники, `.git` и dev-окружение остаются
на сборщике. `import` разворачивает образы через `docker load` и удаляет
временный tar.

Выборочно работают все три команды: `build-images.sh export dashboard`,
`build-images.sh import nginx pg`, `build-images.sh all dashboard`.

### Шпаргалка по `build-images.sh`

| Команда | Действие |
|---|---|
| `build-images.sh [build] [<name>...]` | Собрать все или выбранные образы |
| `build-images.sh export [<name>...]` | Упаковать образы + deploy-файлы в `ownca-images.tar.gz` |
| `build-images.sh import [<name>...]` | Загрузить образы из распакованного `docker-images.tar` |
| `build-images.sh all [<name>...]` | `build` + `export` |
| `build-images.sh help` | Справка |

## Состав стека

| Контейнер | Образ | Порт |
|---|---|---|
| `ownca-gh-demo-postgresql` | `postgres:16` | 5433 |
| `ownca-gh-demo-nginx` | `ownca-nginx:latest` | 9443 (ГОСТ + RSA TLS) |
| `ownca-gh-demo-dashboard` | `ownca-dashboard:latest` | 9000 (Django) |

```
Браузер ──> nginx :9443 (ГОСТ + RSA TLS)
                |
          Dashboard :9000
                |--> openssl + gost-engine   (генерация ключей и подпись)
                |--> CryptoPro CSP / CAPILite (опционально — российская криптография)
                |--> /var/lib/ownca           (УЦ, сертификаты, CRL на диске)
                |--> PostgreSQL :5433         (индекс метаданных)
```

Все сервисы работают в `network_mode: host`, поэтому порты 5433/9000/9443
занимаются на самом хосте. Проект зафиксирован как `ownca_gh_demo` — имена
контейнеров, томов и сети не зависят от имени каталога, в который распакован
архив.

## Настройка

Переменные задаются в файле `.env` рядом с `docker-compose.yml`; шаблон —
`.env.example`.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Логин администратора |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Заголовок в верхней панели |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Включить криптопровайдер CryptoPro CSP (действует, только если он запечён в образ) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Серийный номер лицензии (пусто → демонстрационная на 90 дней; значение из панели приоритетнее) |

Полный список переменных приложения — в
[ownca_dashboard/README.md](../ownca_dashboard/README.md).

## Данные и тома

| Том | Что там |
|---|---|
| `ownca_gh_demo_data` | `/var/lib/ownca` — УЦ, ключи openssl-УЦ, выпущенные сертификаты, CRL |
| `ownca_gh_demo_pg_data` | Индекс метаданных PostgreSQL |
| `ownca_gh_demo_certs` | Собственная PKI nginx |
| `ownca_gh_demo_cryptopro_keys` | Контейнеры ключей CryptoPro (`/var/opt/cprocsp/keys`) |
| `ownca_gh_demo_cryptopro_gamma` | Гамма ДСЧ CryptoPro (`/var/opt/cprocsp/dsrf`) |

Опубликованные CRL дополнительно монтируются из каталога `demo/crls/`.

```bash
docker compose down      # остановка, данные целы
docker compose down -v   # полная очистка, включая ключи CryptoPro и гамму
```

> Ключи CryptoPro-УЦ лежат **не** в `ownca_gh_demo_data`, а в
> `ownca_gh_demo_cryptopro_keys`. Резервировать нужно оба тома, иначе
> восстановленный УЦ не сможет ничего подписать; `down -v` уносит их
> безвозвратно.

## Криптопровайдер CryptoPro CSP (опционально)

Если при сборке dashboard доступен дистрибутив CryptoPro (`.tgz` с
`.deb`-пакетами), он запекается в образ: ставятся пакеты и компилируется
C-мост `ownca_capi` к CAPILite. Путь по умолчанию —
`dev_env/cryptopro_linux-amd64_deb.tgz`:

```bash
OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro_linux-amd64_deb.tgz bash build-images.sh build dashboard
OWNCA_CRYPTOPRO_DIST=none bash build-images.sh   # принудительно БЕЗ CryptoPro
```

Без дистрибутива образ собирается без CryptoPro (с явным сообщением), и вся
российская криптография остаётся на openssl + gost-engine.

С запечённым CryptoPro и `OWNCA_CRYPTOPRO_ENABLED=True` в панели появляется
управление провайдером: состояние, лицензия, остаток гаммы ДСЧ и её загрузка.
Для генерации ключей гамма обязательна — загрузите её или сгенерируйте тестовую
(только для стенда). Ограничения — в корневом
[README](../README.md#ограничения-криптопровайдера-cryptopro).

Порядок работы с панелью описывает встроенная контекстная справка — она
открывается прямо из интерфейса.
