# OwnCA Dashboard

**Русский** | [English](README.en.md)

---

Django-приложение веб-панели УЦ. Что панель умеет с точки зрения оператора —
в корневом [README](../README.md); здесь техническая часть: структура кода,
раскладка на диске, переменные окружения.

## Структура

| Путь | Что там |
|---|---|
| `config/` | Настройки Django, корневой `urls.py`, WSGI/ASGI |
| `dashboard/own_ca.py` | Всё взаимодействие с криптографией: обёртки над `openssl` и мостом `ownca_capi`, сборка конфигов УЦ, выпуск, отзыв, CRL, PKCS#12, разбор X.509 |
| `dashboard/cryptopro.py` | Статус провайдера CryptoPro, лицензия, гамма ДСЧ |
| `dashboard/models.py` | `CertificateAuthority`, `Certificate`, `CertProfile`, реестр OID-полей, системные настройки |
| `dashboard/views.py`, `urls.py` | Представления панели и внутренние JSON-эндпоинты |
| `dashboard/templates/`, `dashboard/static/` | Шаблоны и статика |
| `dashboard/webhelp/` | Портал справки: `nav.py` + `content/{ru,en}/*.md`, рендер markdown на лету |
| `dashboard/management/commands/` | `ensure_admin`, `cryptopro_setup`, `strip_cert_text` |
| `dashboard/tests/` | Тесты (`manage.py test dashboard`) |
| `capi/` | Исходник C-моста к CAPILite — см. [capi/README.md](capi/README.md) |
| `locale/` | Переводы `ru` / `en` |

`own_ca.py` поднимает единственный тип исключения `OwnCAError`, чтобы слой
представлений показывал оператору одну понятную ошибку независимо от того,
что именно упало внутри.

## Хранилище на диске

БД хранит только индекс метаданных для фильтрации и листинга; первоисточник —
файлы под `OWNCA_STORAGE_DIR`. Все пути вычисляются от строки модели
(`.storage_dir`, `.cert_path`, `.key_path`, …).

```
cas/<uuid>/
    ca.crt                 сертификат УЦ (PEM)
    ca.key                 закрытый ключ openssl-УЦ (PEM, 0600); у CryptoPro-УЦ его нет
    backend                'openssl' или 'capilite:<контейнер>' — фиксируется при создании
    subject_x500           точная строка DN, использованная при создании (стабильность цепочки)
    openssl.cnf            конфиг для операций `openssl ca`
    index.txt[.attr]       база выпущенных сертификатов openssl
    serial, crlnumber      счётчики (hex)
    crl_days               срок действия CRL
    crl.pem                последний выпущенный CRL
    newcerts/<SERIAL>.pem  копии подписанных сертификатов
certs/<uuid>/
    cert.pem               сертификат
    key.pem                закрытый ключ (0600) — только при серверной генерации
    csr.pem                запрос (пишется всегда)
crls/
    <имя_УЦ>.crl           публикуемые копии, действие «Rebuild all CRLs»
```

Маркер `backend` — авторитетный источник того, каким провайдером подписывает
данный УЦ; УЦ, созданные до появления CryptoPro, считаются openssl. У
CryptoPro-УЦ закрытый ключ лежит в контейнере провайдера
(`/var/opt/cprocsp/keys`), а не здесь — это важно для резервного копирования.

## Архитектура

```
Браузер ──> nginx (ГОСТ + RSA TLS) ──> Django
                                         |--> openssl (+ gost-engine)
                                         |--> ownca_capi ──> CryptoPro CSP  (опционально)
                                         |--> OWNCA_STORAGE_DIR  (ключи, сертификаты, CRL)
                                         |--> PostgreSQL         (индекс метаданных)
```

Конкретные порты и тома зависят от окружения — см. [dev_env](../dev_env/) и
[demo](../demo/).

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DJANGO_SECRET_KEY` | небезопасный dev-ключ | Ключ подписи Django — обязательно свой вне стенда |
| `DJANGO_DEBUG` | `True` | Режим отладки |
| `DJANGO_ALLOWED_HOSTS` | `*` | Разрешённые хосты (через запятую) |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:8000,http://localhost:8000` | Origin'ы для CSRF |
| `DJANGO_SECURE_COOKIES` | `True` | Флаг `Secure` на cookie сессии; выключается только для доступа по HTTP |
| `DJANGO_LOG_LEVEL` | `INFO` | Уровень логирования приложения |
| `DB_HOST` / `DB_PORT` | `127.0.0.1` / `5432` | PostgreSQL |
| `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `ownca` / `ownca` / `ownca` | Параметры БД |
| `DASHBOARD_ADMIN_USER` | `admin` | Логин администратора (создаётся `ensure_admin`) |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Длинный заголовок в верхней панели |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Каталог материалов УЦ и сертификатов |
| `OWNCA_OPENSSL_BIN` | `openssl` | Путь к бинарю openssl |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Алгоритм ключей по умолчанию |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Срок действия УЦ по умолчанию (дней) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Срок действия сертификата по умолчанию (дней) |
| `OWNCA_CRL_DISTRIBUTION` | — | Публичный URL раздачи CRL (информационно) |
| `UPLOAD_MAX_MB` | `10` | Предельный размер загружаемого файла |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Включить криптопровайдер CryptoPro (действует только при наличии маркера сборки) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Серийный номер лицензии; значение из панели приоритетнее |
| `OWNCA_CRYPTOPRO_MARKER` | `/opt/ownca/.cryptopro_available` | Маркер сборки с CryptoPro |
| `OWNCA_CRYPTOPRO_ROOT` | `/opt/cprocsp` | Корень установки CryptoPro |
| `OWNCA_CRYPTOPRO_GAMMA_DIR` | `/var/opt/cprocsp/dsrf` | Каталог гаммы ДСЧ |
| `OWNCA_CRYPTOPRO_SHIM_BIN` | `/opt/ownca/bin/ownca_capi` | Мост к CAPILite |

Маркер и мост намеренно лежат **вне** `/opt/app`: dev-стек монтирует туда
исходники и перекрыл бы всё, что образ туда положил.

## Криптопровайдеры

- **openssl (+ gost-engine)** — по умолчанию; RSA, ECDSA, Ed25519 и ГОСТ Р
  34.10-2012 (256 / 512) с хешами ГОСТ Р 34.11-2012 и SHA-256. Ключи лежат на
  диске в PEM.
- **CryptoPro CSP** — опциональный сертифицированный провайдер для российской
  криптографии; ключ не
  покидает контейнер провайдера. Включается на сборке и на запуске, выбирается
  на уровне отдельного УЦ. Ограничения — в корневом
  [README](../README.md#ограничения-криптопровайдера-cryptopro), устройство
  моста — в
  [capi/README.md](capi/README.md).

При тестах `OWNCA_CRYPTOPRO_ENABLED` принудительно выключается: набор тестов
проверяет openssl и должен вести себя одинаково на образе с CryptoPro и
без него. Тесты самого CryptoPro включают флаг точечно и подменяют вызовы
моста.

## Разработка

Тесты, переводы, работа с webhelp и команды `manage.py` — всё выполняется
внутри контейнера dev-стека, см. [dev_env/README.md](../dev_env/README.md).
