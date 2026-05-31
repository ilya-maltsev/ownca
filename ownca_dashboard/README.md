# OwnCA Dashboard

**Русский** | [English](README.en.md)

---

Веб-интерфейс для управления удостоверяющим центром, выпускающим
сертификаты с использованием
[gost-engine](https://github.com/gost-engine/engine) (ГОСТ Р 34.10-2012 /
ГОСТ Р 34.11-2012). Поддерживает фильтрацию, отзыв, перевыпуск и экспорт в
PKCS#12.

## Возможности

- **Удостоверяющие центры** — создание корневых и промежуточных УЦ (ГОСТ
  или RSA), просмотр Subject/Issuer/Serial/Fingerprint/дат, скачивание
  сертификата УЦ.
- **Сертификаты** — список выпущенных сертификатов с фильтром по УЦ и
  статусу, просмотр X.509-деталей, скачивание сертификата / ключа /
  CSR / PEM-bundle / PKCS#12, отзыв с указанием причины, перевыпуск.
- **Cert Issue** — выбор УЦ + опционального профиля, заполнение Subject DN
  и SAN, серверная генерация ключа или загрузка внешнего CSR. Свободный
  режим позволяет указать произвольные KU / EKU / расширения / OID без
  привязки к профилю.
- **Cert Profiles** — шаблоны расширений (KU, EKU, basicConstraints,
  name constraints, policy constraints, переопределения точек
  распространения, пользовательские OID-поля).
- **CRL** — автоматическая регенерация при каждом отзыве, ручная
  регенерация со страницы УЦ, скачивание в PEM. Действие «Rebuild all
  CRLs» (Maintenance) дополнительно публикует CRL каждого включённого УЦ
  в `crls/<имя_УЦ>.crl`.
- **System** — страница Configuration (сводка переменных окружения),
  Maintenance (версия openssl, статус gost-engine, обновление метаданных
  с диска, перестроение всех CRL).
- **Webhelp** — встроенный портал контекстной справки на `/webhelp/`.
- **i18n** — русский (по умолчанию) и английский, переключение в боковой
  панели.
- **Аутентификация** — вход с единственной admin-учётной записью,
  настраиваемой через переменные окружения.

## Архитектура

```
                       nginx :8443 (ГОСТ + RSA TLS)
                              |
Браузер -----> nginx ------> Dashboard :8000
                                   |
                                   |--> PostgreSQL :5432  (индекс метаданных)
                                   |
                                   |--> /var/lib/ownca/   (ключи, сертификаты, CRL)
```

Весь материал ключей и сертификатов хранится на диске в каталоге
`OWNCA_STORAGE_DIR`; БД содержит только индекс метаданных для быстрой
фильтрации и листинга.

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DB_HOST` | `127.0.0.1` | Хост PostgreSQL |
| `DB_PORT` | `5432` | Порт PostgreSQL |
| `DB_NAME` | `ownca` | Имя БД |
| `DB_USER` | `ownca` | Пользователь БД |
| `DB_PASSWORD` | `ownca` | Пароль БД |
| `DASHBOARD_ADMIN_USER` | `admin` | Логин admin по умолчанию |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Пароль admin по умолчанию |
| `OWNCA_PROJECT_NAME` | `OwnCA` | Бренд в шапке/сайдбаре |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Длинный заголовок в topbar |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Путь к материалам УЦ и сертификатам |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Алгоритм ключей по умолчанию |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Срок действия CA по умолчанию (дней) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Срок действия сертификата по умолчанию (дней) |
| `OWNCA_CRL_DISTRIBUTION` | — | Публичный URL раздачи CRL (информационно) |

## Поддерживаемые алгоритмы

- **ГОСТ Р 34.10-2012** (256-bit, 512-bit) — ключи, подписи
- **ГОСТ Р 34.11-2012** — хеш-функции
- **RSA** (2048, 4096) — fallback для окружений без gost-engine
- **ECDSA** (P-256, P-384) и **Ed25519** — также поддерживаются

## Профили сертификатов из коробки

| Профиль | Key Usage | Extended Key Usage |
|---|---|---|
| `server` | digitalSignature, keyEncipherment, keyAgreement | serverAuth |
| `client` | digitalSignature, keyEncipherment, dataEncipherment, keyAgreement | clientAuth |
| `server_client` | digitalSignature, keyEncipherment | serverAuth, clientAuth |
| `vpn` | digitalSignature | serverAuth, clientAuth |
| `user` | digitalSignature, keyEncipherment | clientAuth, emailProtection |
| `user_login` | digitalSignature, keyEncipherment | clientAuth + smartcard logon OID |
| `smartcard_logon` | digitalSignature | smartcard logon OID |
| `smime_sign` | digitalSignature, nonRepudiation | emailProtection |
| `code_signing` | digitalSignature | codeSigning |
| `timestamping` | digitalSignature | timeStamping (critical) |
