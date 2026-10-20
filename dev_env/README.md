# OwnCA — окружение разработки

**Русский** | [English](README.en.md)

---

Окружение Docker для разработки на своём компьютере: образы собираются из
исходного кода, а код панели подключается в контейнер, поэтому изменения
применяются без перезапуска. Описание самой программы — в корневом
[README](../README.md).

## Быстрый старт

```bash
cd dev_env
docker compose up -d --build
```

Адреса панели:

| Адрес | Назначение |
|---|---|
| `https://127.0.0.1:8444` | через nginx (TLS по ГОСТ и RSA) — проверка всей цепочки |
| `http://127.0.0.1:8001` | напрямую к Django — для отладки |

Учётная запись по умолчанию: `admin` / `admin`. PostgreSQL снаружи
недоступен — только из сети `gh_ownca_devnet`.

При первом запуске автоматически создаётся база данных `ownca`, выпускаются
сертификаты ГОСТ и RSA для nginx, применяются миграции Django и создаётся
учётная запись администратора.

## Состав

| Файл | Назначение |
|---|---|
| `docker-compose.yml` | Три службы: `gh_ownca_dev_postgresql`, `gh_ownca_dev_nginx`, `gh_ownca_dev_dashboard` |
| `build.sh` | Сборка образов, при наличии дистрибутива — с CryptoPro CSP |
| `init-db.sh` | Подготовка базы данных при первом запуске PostgreSQL |
| `postgresql.conf`, `pg_hba.conf` | Настройки PostgreSQL |
| `dashboard/Dockerfile` | Образ с Django, OpenSSL и gost-engine (и CryptoPro CSP, если при сборке передан дистрибутив) |
| `dashboard/entrypoint.sh` | Действия при запуске панели |
| `dashboard/vendor/` | Временная копия дистрибутива CryptoPro на время сборки (её создаёт и удаляет `build.sh`) |
| `nginx/Dockerfile`, `nginx/entrypoint.sh` | nginx с поддержкой TLS по ГОСТ и собственными сертификатами |
| `nginx/nginx.conf` | Настройки TLS и передачи запросов на `dashboard:8001` |
| `nginx/openssl-gost.cnf` | Настройки OpenSSL с подключённым gost-engine |

Имена проекта, контейнеров, сети и томов начинаются с `gh_ownca`. Без явного
`name:` Compose взял бы имя проекта из названия каталога (`dev_env`), и два
таких окружения на одном сервере незаметно использовали бы одни и те же тома.

## Применение изменений без перезапуска

Каталог `ownca_dashboard/` подключён в контейнер как `/opt/app`: изменения в
коде на Python, шаблонах и статических файлах Django применяет сразу.
Пересобирать образ нужно только после изменения `requirements.txt` или
`Dockerfile`.

Исключение — программа `ownca_dashboard/capi/ownca_capi.c` (обёртка на C над
CAPILite): она компилируется при сборке образа. Как перекомпилировать её
без пересборки образа, описано в
[capi/README.md](../ownca_dashboard/capi/README.md).

## Действия при запуске

`dashboard/entrypoint.sh` при каждом запуске выполняет: `compilemessages`
(изменения переводов применяются без отдельной команды) → `collectstatic` →
`migrate` → `ensure_admin` → `cryptopro_setup` (без CryptoPro ничего не
делает) → `runserver $BIND_ADDRESS`.

`nginx/entrypoint.sh` при первом запуске создаёт в томе `certs` собственные
сертификаты nginx: УЦ и сертификат сервера по ГОСТ (`gost2012_256`, набор
параметров A), а также пару ключ–сертификат RSA для обычных браузеров. Эти
сертификаты нужны **только nginx** и никак не связаны с УЦ, которыми управляет
OwnCA. При следующих запусках они не создаются заново, если в томе уже есть
`ca.crt`. Дополнительные имена (SAN) задаются через `CERT_EXTRA_SANS`, срок
действия — через `CERT_DAYS`.

## Где хранятся данные

| Путь в контейнере | Содержимое | Том |
|---|---|---|
| `/var/lib/ownca` | Сертификаты УЦ, выпущенные сертификаты, запросы, CRL, счётчики, отметки о криптопровайдере; закрытые ключи УЦ на **OpenSSL** (PEM, права `0600`) | `gh_ownca_data` |
| `/var/lib/ownca/crls` | Опубликованные CRL — отдельно подключённый каталог, чтобы раздавать их наружу | каталог `dev_env/crls/` |
| `/var/opt/cprocsp/keys` | Контейнеры CryptoPro с закрытыми ключами ГОСТ-УЦ и сертификатов | `gh_ownca_cryptopro_keys` |
| `/var/opt/cprocsp/dsrf` | Гамма ДСЧ (`db1/kis_1`, `db2/kis_1`) | `gh_ownca_cryptopro_gamma` |
| `/etc/nginx/certs` | Собственные сертификаты nginx | `gh_ownca_certs` |
| `/var/lib/postgresql/data` | Сведения для поиска и списков | `gh_ownca_pg_data` |
| `/opt/cprocsp`, `/opt/ownca/bin/ownca_capi` | CryptoPro CSP и обёртка над CAPILite | в образе |

Гамма вынесена в отдельный том намеренно: она расходуется (36 байт на каждую
генерацию ключа) и должна сохраняться при перезапуске — иначе после каждого
перезапуска генерация ключей была бы невозможна до новой загрузки гаммы.

> **Резервное копирование.** Закрытые ключи УЦ на CryptoPro хранятся **не** в
> `/var/lib/ownca`, а в контейнерах в `/var/opt/cprocsp/keys`. Копия одного
> каталога хранилища сохранит сертификаты, но не ключи, и восстановленный УЦ
> ничего подписать не сможет. Копируйте оба тома одновременно.

## Переменные окружения

Задаются в файле `dev_env/.env`, который Docker Compose читает автоматически.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Имя администратора |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `DB_HOST` | `gh_ownca_dev_postgresql` | Сервер PostgreSQL |
| `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `5432` / `ownca` / `ownca` / `ownca` | Параметры подключения к базе данных |
| `DJANGO_DEBUG` | `True` | Режим отладки Django |
| `DJANGO_ALLOWED_HOSTS` | `*` | Допустимые имена сервера |
| `CSRF_TRUSTED_ORIGINS` | список из `docker-compose.yml` | Доверенные адреса для защиты от CSRF |
| `DJANGO_SECURE_COOKIES` | `False` в этом окружении (в самом приложении — `True`) | Признак `Secure` у cookie сеанса; здесь выключен, чтобы работал доступ по `http://…:8001` |
| `DJANGO_SECRET_KEY` | небезопасный ключ для разработки | Секретный ключ Django |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Заголовок в верхней части панели |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Каталог хранения УЦ и сертификатов |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Алгоритм ключа по умолчанию |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Срок действия УЦ по умолчанию, дней |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Срок действия сертификата по умолчанию, дней |
| `OWNCA_CRL_DISTRIBUTION` | — | Адрес публикации CRL (только для справки) |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Включить CryptoPro при запуске (действует, только если CryptoPro установлен в образ) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Серийный номер лицензии (если не задан — демонстрационная лицензия на 90 дней; номер, введённый в панели, имеет приоритет) |
| `OWNCA_CRYPTOPRO_GAMMA_DIR` | `/var/opt/cprocsp/dsrf` | Каталог гаммы ДСЧ |
| `OWNCA_CRYPTOPRO_ROOT` | `/opt/cprocsp` | Каталог установки CryptoPro |
| `OWNCA_CRYPTOPRO_SHIM_BIN` | `/opt/ownca/bin/ownca_capi` | Путь к обёртке над CAPILite |
| `OWNCA_CRYPTOPRO_MARKER` | `/opt/ownca/.cryptopro_available` | Файл-признак того, что образ собран с CryptoPro |
| `UPLOAD_MAX_MB` | `10` | Наибольший размер загружаемого файла, МБ |
| `BIND_ADDRESS` | `0.0.0.0:8001` | Адрес, на котором `runserver` принимает соединения в контейнере |

Переменная сборки (для `build.sh`, а не для контейнера):

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `OWNCA_CRYPTOPRO_DIST` | `dev_env/cryptopro_linux-amd64_deb.tgz` | Путь к дистрибутиву CryptoPro (`.tgz` с пакетами `.deb`); `none` — собрать без CryptoPro |

Для контейнера nginx: `CERT_DAYS` (по умолчанию `365`) и `CERT_EXTRA_SANS`
(например, `DNS:foo,IP:1.2.3.4`).

## Типовые действия

Все команды выполняются внутри контейнеров, чтобы ничего не устанавливать на
основную систему.

```bash
D='docker compose -f dev_env/docker-compose.yml exec'

# тесты (нужно право CREATEDB — см. ниже)
$D gh_ownca_dev_dashboard python manage.py test dashboard -v2

# консоль Django и служебные команды
$D gh_ownca_dev_dashboard python manage.py shell
$D gh_ownca_dev_dashboard python manage.py makemigrations

# PostgreSQL
$D gh_ownca_dev_postgresql psql -U ownca -d ownca

# переводы — после изменения строк в коде или шаблонах
$D gh_ownca_dev_dashboard python manage.py makemessages -l ru -l en

# журнал
docker compose -f dev_env/docker-compose.yml logs -f gh_ownca_dev_dashboard
```

Для тестов Django создаёт отдельную базу данных на том же сервере PostgreSQL,
поэтому пользователю базы нужно право `CREATEDB` (выдаётся один раз):

```bash
docker compose -f dev_env/docker-compose.yml exec gh_ownca_dev_postgresql \
    psql -U postgres -c "ALTER USER ownca CREATEDB;"
```

Файлы `.po` переводятся вручную; `compilemessages` выполняется при каждом
запуске контейнера, отдельно его запускать не нужно.

**Справка.** Тексты встроенной справки лежат в
`ownca_dashboard/dashboard/webhelp/content/{ru,en}/*.md` и преобразуются в
HTML при обращении, но результат кешируется (`lru_cache`). Поэтому изменения
в `.md` без перезапуска **не** видны — выполните
`docker compose … restart gh_ownca_dev_dashboard`. Изменения в
`webhelp/nav.py` и других файлах `.py` применяются как обычно.

## Сброс окружения

```bash
docker compose -f dev_env/docker-compose.yml down      # остановка, данные сохраняются
docker compose -f dev_env/docker-compose.yml down -v   # полная очистка
```

> `down -v` удаляет и контейнеры ключей CryptoPro вместе с гаммой: ключи всех
> УЦ на CryptoPro будут безвозвратно потеряны.

## Криптопровайдер CryptoPro CSP (дополнительно)

Дистрибутив CryptoPro (`.tgz` с пакетами `.deb`) в репозиторий не входит.
CryptoPro подключается в два этапа — при сборке образа и при запуске:

```bash
# положите cryptopro_linux-amd64_deb.tgz в dev_env/ и выполните:
dev_env/build.sh
# или укажите путь явно:
OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro_linux-amd64_deb.tgz dev_env/build.sh

# затем включите CryptoPro при запуске:
echo 'OWNCA_CRYPTOPRO_ENABLED=True' >> dev_env/.env
cd dev_env && docker compose up -d
```

`build.sh` копирует дистрибутив в `dashboard/vendor/cryptopro.tgz`, запускает
`docker compose build` и удаляет копию. При сборке образа устанавливаются
пакеты (версия определяется по имени пакета в архиве), компилируется
`ownca_dashboard/capi/ownca_capi.c` в `/opt/ownca/bin/ownca_capi` и создаётся
файл-признак `/opt/ownca/.cryptopro_available`. Если дистрибутива нет, образ
собирается без CryptoPro (об этом выводится сообщение), и переменная
`OWNCA_CRYPTOPRO_ENABLED` в таком образе ни на что не влияет.

CryptoPro управляется на странице «Обслуживание»: состояние, лицензия,
остаток гаммы ДСЧ и её загрузка. На сервере без графического интерфейса без
гаммы генерация ключей завершается ошибкой `NTE_SILENT_CONTEXT (0x80090022)`:
CryptoPro пытается запросить случайные данные у пользователя через диалоговое
окно, а сеанс открыт в режиме `CRYPT_SILENT`, где диалоги запрещены. Там же
можно сгенерировать тестовую гамму — только для стенда.

Ограничения описаны в корневом
[README](../README.md#ограничения-криптопровайдера-cryptopro), устройство
обёртки над CAPILite — в [capi/README.md](../ownca_dashboard/capi/README.md).

## Схема окружения

```
Браузер ──> gh_ownca_dev_nginx :8444 ──> gh_ownca_dev_dashboard :8001 ──> gh_ownca_dev_postgresql :5432
                  ^                       |                       (gh_ownca_devnet)
                  |                       |
            том: certs              том: ownca_data
            (TLS ГОСТ и RSA)        (УЦ, ключи, CRL)
```

Все службы работают в отдельной сети Docker `gh_ownca_devnet`; снаружи
доступны только порты `8444` и `8001`.
