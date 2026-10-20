# OwnCA — веб-панель

**Русский** | [English](README.en.md)

---

Приложение Django, на котором работает веб-панель УЦ. Возможности панели с
точки зрения пользователя описаны в корневом [README](../README.md); здесь —
устройство кода, хранение данных на диске и переменные окружения.

## Структура

| Путь | Содержимое |
|---|---|
| `config/` | Настройки Django, корневой `urls.py`, WSGI/ASGI |
| `dashboard/own_ca.py` | Все криптографические операции: вызовы `openssl` и обёртки `ownca_capi`, создание файлов настроек УЦ, выпуск, отзыв, CRL, PKCS#12, разбор X.509 |
| `dashboard/cryptopro.py` | Состояние CryptoPro, лицензия, гамма ДСЧ |
| `dashboard/models.py` | `CertificateAuthority`, `Certificate`, `CertProfile`, реестр OID, системные настройки |
| `dashboard/views.py`, `urls.py` | Страницы панели и служебные запросы, возвращающие JSON |
| `dashboard/templates/`, `dashboard/static/` | Шаблоны и статические файлы |
| `dashboard/webhelp/` | Встроенная справка: `nav.py` и тексты `content/{ru,en}/*.md`, которые преобразуются в HTML при обращении |
| `dashboard/management/commands/` | `ensure_admin`, `cryptopro_setup`, `strip_cert_text` |
| `dashboard/tests/` | Тесты (`manage.py test dashboard`) |
| `capi/` | Исходный код обёртки на C над CAPILite — см. [capi/README.md](capi/README.md) |
| `locale/` | Переводы `ru` / `en` |

Все ошибки `own_ca.py` сообщает исключением одного типа — `OwnCAError`, поэтому
пользователь видит понятное сообщение, на каком бы шаге ни произошёл сбой.

## Хранение данных на диске

База данных содержит только сведения для поиска и вывода списков; основной
источник данных — файлы в каталоге `OWNCA_STORAGE_DIR`. Пути к файлам
вычисляются по записи в базе (`.storage_dir`, `.cert_path`, `.key_path`, …).

```
cas/<uuid>/
    ca.crt                 сертификат УЦ (PEM)
    ca.key                 закрытый ключ УЦ на OpenSSL (PEM, 0600); у УЦ на CryptoPro его нет
    backend                'openssl' или 'capilite:<контейнер>' — задаётся при создании
    subject_x500           точная строка DN, заданная при создании (поле Issuer выпускаемых сертификатов совпадает с ней байт в байт)
    openssl.cnf            настройки для `openssl ca`
    index.txt[.attr]       перечень выпущенных сертификатов в формате openssl
    serial, crlnumber      счётчики (шестнадцатеричные)
    crl_days               срок действия CRL
    crl.pem                последний выпущенный CRL
    newcerts/<SERIAL>.pem  копии подписанных сертификатов
certs/<uuid>/
    cert.pem               сертификат
    key.pem                закрытый ключ (0600) — только если ключ создан на сервере
    csr.pem                запрос на сертификат (создаётся всегда)
crls/
    <имя_УЦ>.crl           копии для публикации; их создаёт действие «Rebuild all CRLs»
```

Файл `backend` определяет, каким криптопровайдером подписывает УЦ; УЦ без
этого файла (созданные до появления поддержки CryptoPro) работают на OpenSSL.
У УЦ на CryptoPro закрытый ключ хранится не здесь, а в контейнере
(`/var/opt/cprocsp/keys`) — это важно учитывать при резервном копировании.

## Схема работы

```
Браузер ──> nginx (TLS по ГОСТ и RSA) ──> Django
                                            |--> openssl (+ gost-engine)
                                            |--> ownca_capi ──> CryptoPro CSP  (дополнительно)
                                            |--> OWNCA_STORAGE_DIR  (ключи, сертификаты, CRL)
                                            |--> PostgreSQL         (сведения для поиска и списков)
```

Порты и тома зависят от окружения — см. [dev_env](../dev_env/) и
[demo](../demo/).

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `DJANGO_SECRET_KEY` | небезопасный ключ для разработки | Секретный ключ Django; вне стенда обязательно задайте свой |
| `DJANGO_DEBUG` | `True` | Режим отладки |
| `DJANGO_ALLOWED_HOSTS` | `*` | Допустимые имена сервера (через запятую) |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:8000,http://localhost:8000` | Доверенные адреса для защиты от CSRF |
| `DJANGO_SECURE_COOKIES` | `True` | Признак `Secure` у cookie сеанса; выключайте только для доступа по HTTP |
| `DJANGO_LOG_LEVEL` | `INFO` | Уровень подробности журнала |
| `DB_HOST` / `DB_PORT` | `127.0.0.1` / `5432` | Сервер PostgreSQL |
| `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `ownca` / `ownca` / `ownca` | Параметры подключения к базе данных |
| `DASHBOARD_ADMIN_USER` | `admin` | Имя администратора (учётную запись создаёт `ensure_admin`) |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль администратора |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Заголовок в верхней части панели |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Каталог хранения УЦ и сертификатов |
| `OWNCA_OPENSSL_BIN` | `openssl` | Путь к программе `openssl` |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Алгоритм ключа по умолчанию |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Срок действия УЦ по умолчанию, дней |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Срок действия сертификата по умолчанию, дней |
| `OWNCA_CRL_DISTRIBUTION` | — | Адрес публикации CRL (только для справки) |
| `UPLOAD_MAX_MB` | `10` | Наибольший размер загружаемого файла, МБ |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Включить CryptoPro (действует, только если образ собран с CryptoPro) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Серийный номер лицензии; номер, введённый в панели, имеет приоритет |
| `OWNCA_CRYPTOPRO_MARKER` | `/opt/ownca/.cryptopro_available` | Файл-признак того, что образ собран с CryptoPro |
| `OWNCA_CRYPTOPRO_ROOT` | `/opt/cprocsp` | Каталог установки CryptoPro |
| `OWNCA_CRYPTOPRO_GAMMA_DIR` | `/var/opt/cprocsp/dsrf` | Каталог гаммы ДСЧ |
| `OWNCA_CRYPTOPRO_SHIM_BIN` | `/opt/ownca/bin/ownca_capi` | Путь к обёртке над CAPILite |

Файл-признак и обёртка намеренно расположены **вне** `/opt/app`: в окружении
разработки в этот каталог подключается исходный код, и всё, что было
помещено туда при сборке образа, оказалось бы недоступно.

## Криптопровайдеры

- **OpenSSL (с gost-engine)** — используется по умолчанию: RSA, ECDSA, Ed25519
  и ГОСТ Р 34.10-2012 (256 / 512 бит) с хеш-функциями ГОСТ Р 34.11-2012 и
  SHA-256. Ключи хранятся на диске в формате PEM.
- **CryptoPro CSP** — дополнительный сертифицированный криптопровайдер для
  ГОСТ; ключ не покидает контейнер. Устанавливается при сборке образа,
  включается при запуске и выбирается для каждого УЦ отдельно. Ограничения
  описаны в корневом
  [README](../README.md#ограничения-криптопровайдера-cryptopro), устройство
  обёртки — в [capi/README.md](capi/README.md).

На время тестов `OWNCA_CRYPTOPRO_ENABLED` принудительно выключается: тесты
проверяют работу через OpenSSL и должны давать одинаковый результат на образе
с CryptoPro и без него. Тесты CryptoPro включают его только для себя и
заменяют вызовы обёртки заглушками.

## Разработка

Тесты, переводы, правка справки и команды `manage.py` выполняются внутри
контейнера окружения разработки — см. [dev_env/README.md](../dev_env/README.md).
