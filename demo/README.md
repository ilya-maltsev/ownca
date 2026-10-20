# OwnCA — демонстрационное окружение

**Русский** | [English](README.en.md)

---

Окружение для демонстрации: запускается одной командой из заранее собранных
образов. Описание самой программы — в корневом [README](../README.md).

Оба варианта использования обслуживает сценарий `build-images.sh`:

1. **На этом компьютере** — собрать образы и запустить окружение.
2. **На изолированном сервере** — собрать образы один раз, упаковать их вместе
   с файлами развёртывания в один архив `tar.gz`, перенести на сервер без
   доступа в интернет и запустить там.

## 1. Сборка и запуск на этом компьютере

```bash
cd demo
bash build-images.sh          # то же, что build-images.sh build
docker compose up -d
```

Сборка загружает образ `postgres:16` и собирает два своих: `ownca-nginx:latest`
(nginx с поддержкой TLS по ГОСТ) и `ownca-dashboard:latest` (Django, OpenSSL и
gost-engine); файлы Dockerfile берутся из `dev_env/`. В образ попадают только
файлы из явного списка (`DASHBOARD_FILES`, `NGINX_FILES` в сценарии):
документация, `.git`, средства разработки и рабочие данные в него не входят.

Первый запуск занимает около 30 секунд: создаются база данных и пользователь
`ownca`, выпускаются сертификаты ГОСТ и RSA для nginx, затем выполняются
`compilemessages`, `collectstatic`, `migrate`, `ensure_admin` и
`cryptopro_setup` (без CryptoPro последняя ничего не делает).

Панель открывается по адресу `https://localhost:9443`, учётная запись —
`admin` / `admin`.

### Сборка отдельных образов

```bash
bash build-images.sh build dashboard      # только ownca-dashboard
bash build-images.sh build dash nginx     # несколько образов
```

Краткие имена: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).

## 2. Перенос на изолированный сервер

```bash
# на компьютере, где собираются образы
cd demo
bash build-images.sh all                  # сборка и упаковка

# на целевом сервере
tar xzf ownca-images.tar.gz -C /opt/
cd /opt/demo
bash build-images.sh import
docker compose up -d
```

Команда `export` упаковывает всё в один файл `demo/ownca-images.tar.gz`: в
нём `docker-images.tar` (все образы, сохранённые `docker save`) и файлы
развёртывания (список `DEPLOY_PATHS` в сценарии) — сам сценарий,
`docker-compose.yml`, `.env.example`, `init-db.sh`, `nginx.conf` и README.
Исходный код, `.git` и окружение разработки в архив не попадают. Команда
`import` загружает образы через `docker load` и удаляет временный файл.

Все три команды можно применить к отдельным образам:
`build-images.sh export dashboard`, `build-images.sh import nginx pg`,
`build-images.sh all dashboard`.

### Команды `build-images.sh`

| Команда | Действие |
|---|---|
| `build-images.sh [build] [<имя>...]` | Собрать все или указанные образы |
| `build-images.sh export [<имя>...]` | Упаковать образы и файлы развёртывания в `ownca-images.tar.gz` |
| `build-images.sh import [<имя>...]` | Загрузить образы из распакованного `docker-images.tar` |
| `build-images.sh all [<имя>...]` | `build` и затем `export` |
| `build-images.sh help` | Справка |

## Состав окружения

| Контейнер | Образ | Порт |
|---|---|---|
| `ownca-gh-demo-postgresql` | `postgres:16` | 5433 |
| `ownca-gh-demo-nginx` | `ownca-nginx:latest` | 9443 (TLS по ГОСТ и RSA) |
| `ownca-gh-demo-dashboard` | `ownca-dashboard:latest` | 9000 (Django) |

```
Браузер ──> nginx :9443 (TLS по ГОСТ и RSA)
                |
          Панель :9000
                |--> OpenSSL + gost-engine    (генерация ключей и подпись)
                |--> CryptoPro CSP / CAPILite (дополнительно — ГОСТ-операции)
                |--> /var/lib/ownca           (УЦ, сертификаты, CRL на диске)
                |--> PostgreSQL :5433         (сведения для поиска и списков)
```

Все службы работают в режиме `network_mode: host`, поэтому порты 5433, 9000
и 9443 заняты непосредственно на сервере. Имя проекта задано явно —
`ownca_gh_demo`, поэтому имена контейнеров, томов и сети не зависят от
каталога, в который распакован архив.

## Настройка

Переменные задаются в файле `.env` рядом с `docker-compose.yml`; образец —
`.env.example`.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Имя администратора |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Заголовок в верхней части панели |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Включить CryptoPro CSP (действует, только если CryptoPro установлен в образ) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Серийный номер лицензии (если не задан — демонстрационная лицензия на 90 дней; номер, введённый в панели, имеет приоритет) |

Полный перечень переменных приведён в
[ownca_dashboard/README.md](../ownca_dashboard/README.md).

## Данные и тома

| Том | Содержимое |
|---|---|
| `ownca_gh_demo_data` | `/var/lib/ownca` — УЦ, ключи УЦ на OpenSSL, выпущенные сертификаты, CRL |
| `ownca_gh_demo_pg_data` | База данных PostgreSQL |
| `ownca_gh_demo_certs` | Собственные сертификаты nginx |
| `ownca_gh_demo_cryptopro_keys` | Контейнеры ключей CryptoPro (`/var/opt/cprocsp/keys`) |
| `ownca_gh_demo_cryptopro_gamma` | Гамма ДСЧ CryptoPro (`/var/opt/cprocsp/dsrf`) |

Опубликованные CRL дополнительно доступны в каталоге `demo/crls/`.

```bash
docker compose down      # остановка, данные сохраняются
docker compose down -v   # полная очистка, включая ключи CryptoPro и гамму
```

> Ключи УЦ на CryptoPro хранятся **не** в `ownca_gh_demo_data`, а в
> `ownca_gh_demo_cryptopro_keys`. Копируйте оба тома, иначе восстановленный УЦ
> ничего подписать не сможет. `down -v` удаляет их безвозвратно.

## Криптопровайдер CryptoPro CSP (дополнительно)

Если при сборке образа панели доступен дистрибутив CryptoPro (`.tgz` с
пакетами `.deb`), он устанавливается в образ, и компилируется обёртка
`ownca_capi` на C над CAPILite. Путь по умолчанию —
`dev_env/cryptopro_linux-amd64_deb.tgz`:

```bash
OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro_linux-amd64_deb.tgz bash build-images.sh build dashboard
OWNCA_CRYPTOPRO_DIST=none bash build-images.sh   # собрать без CryptoPro
```

Без дистрибутива образ собирается без CryptoPro (об этом выводится
сообщение), и все ГОСТ-операции выполняет OpenSSL с gost-engine.

Если CryptoPro установлен в образ и задано `OWNCA_CRYPTOPRO_ENABLED=True`, на
странице «Обслуживание» появляются состояние CryptoPro, лицензия, остаток
гаммы ДСЧ и её загрузка. Без гаммы ключи не генерируются — загрузите её или
сгенерируйте тестовую (только для стенда). Ограничения описаны в корневом
[README](../README.md#ограничения-криптопровайдера-cryptopro).

Работа с панелью описана во встроенной справке, которая открывается прямо из
интерфейса.
