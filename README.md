# OwnCA

**Русский** | [English](README.en.md)

---

Веб-панель удостоверяющего центра (Certificate Authority). Поддерживает выпуск
и отзыв сертификатов с алгоритмами ГОСТ Р 34.10-2012 и RSA, генерацию CRL,
экспорт ключей и сертификатов в форматах PEM и PKCS#12.

## Состав

| Компонент | Описание |
|---|---|
| [ownca_dashboard](ownca_dashboard/) | Веб-панель УЦ (Django) |
| [dev_env](dev_env/) | Docker Compose для dev-окружения (live-reload). См. [dev_env/README.md](dev_env/README.md) |
| [demo](demo/) | Docker Compose для демо-окружения (предсобранные образы). См. [demo/README.md](demo/README.md) |

## Архитектура

```
Браузер ──────> nginx (ГОСТ + RSA TLS)
                       |
              Dashboard
                  |--> /var/lib/ownca
                  |       (CA, выпущенные сертификаты, CRL)
                  |--> PostgreSQL
                          (индекс метаданных)
```

Состояние УЦ (база выпущенных сертификатов, серийные номера, CRL) хранится в
файлах под `OWNCA_STORAGE_DIR/`. PostgreSQL содержит только индекс
метаданных для удобной фильтрации и просмотра.

## Веб-панель

Боковая панель:

| Раздел | Пункты сайдбара |
|---|---|
| **Monitor** | Dashboard |
| **Certificate Operations** | Certificates, Cert Issue |
| **Certification Authority** | Authorities, Cert Profiles |
| **System** | Configuration, Maintenance |

Возможности:

- **Authorities** (`/cas/`) — создание корневых и промежуточных УЦ, выбор
  алгоритма ключа, Subject DN, срока действия. На странице УЦ — поля
  **Distribution points** (CRL/AIA/OCSP/SIA/freshestCRL/issuerAltName).
- **Certificates** (`/certificates/`) — список выпущенных сертификатов с
  фильтром по УЦ и статусу (active / revoked / expired); просмотр X.509
  деталей; скачивание `.crt`, `.key`, `.csr`, PEM-bundle и `.p12`. Для
  ГОСТ-ключей дополнительно доступен экспорт в **TK-26 совместимом
  формате** (`.gost.p12`) — PFX, соответствующий RFC 9337 + RFC 9548:
  keybag и cert envelope упакованы PBES2 / PBKDF2-HMAC-Streebog поверх
  Кузнечик- или Магма-CTR-ACPKM (выбор шифра — в форме экспорта),
  внешний MAC — HMAC-Streebog-512 c KDF из RFC 9548 §3. Сборка идёт
  стандартной командой `openssl pkcs12 -export` против
  gost-engine
  ([`gost-engine/engine`](https://github.com/gost-engine/engine),
  ветка `master`; поддержка RFC 9337 / RFC 9548 влита в апстрим в PR #527).
- **Cert Issue** (`/custom-cert-issue/`) — единая форма выпуска сертификата:
  выбор УЦ, опционального профиля, заполнение Subject DN и SAN.
  Поддерживается импорт CSR или серверная генерация ключа. Для ГОСТ-ключей
  доступен выбор paramset. УЦ может подписывать сертификаты только своего
  семейства ключей (`gost` / `rsa` / `ec` / `ed25519`); список алгоритмов
  в форме фильтруется по выбранному УЦ, а сервер дополнительно отклоняет
  несовместимые запросы.
- **Cert Profiles** (`/cert-profiles/`) — реестр профилей расширений
  (`server`, `client`, `code_signing`, `user`, `smartcard_logon`,
  `user_login`, `smime_sign`, `timestamping`, `vpn`, `server_client`).
  Редактирование KU/EKU, name/policy constraints, переопределений точек
  распространения и привязки **OID-полей**. Кнопка **Copy** клонирует
  профиль.
- **Configuration** (`/system/configuration/`) — переключатели режимов
  выпуска и обзор переменных окружения.
- **Maintenance** (`/system/maintenance/`) — версия openssl, статус
  gost-engine, кнопка **Refresh metadata**.
- **Webhelp** (`/webhelp/`) — двухъязычный портал контекстной справки;
  кнопка **Help** в боковой панели открывает страницу, соответствующую
  текущему разделу UI.
- **Локализация** — русский (по умолчанию) и английский, переключение в
  боковой панели.

## Live Demo

### https://ilya-maltsev.github.io/ownca/ru/dashboard.html

## Поддерживаемые алгоритмы

- Электронная подпись: ГОСТ Р 34.10-2012 (256 / 512 бит), RSA (2048 / 4096),
  ECDSA (P-256, P-384), Ed25519.
- Хеш-функции: ГОСТ Р 34.11-2012, SHA-256.
- TLS (nginx): GOST2012-KUZNYECHIK-KUZNYECHIKOMAC, GOST2012-MAGMA-MAGMAOMAC.

## Профили сертификатов

Профили определяют расширения, KU, EKU и набор OID-полей, заполняемых при
выпуске. Профили по умолчанию:

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

Профили редактируются на `/cert-profiles/`. К каждому профилю можно
привязать набор OID-полей из реестра (DNS Names, IP Addresses, Email, URI,
UPN, СНИЛС, ИНН, ОГРН, ОГРНИП и пр.) — значения задаются в форме выпуска.

## Запуск

Два готовых сценария Docker Compose:

- **[dev_env/](dev_env/)** — live-reload, исходники монтируются в контейнер.
  Подходит для разработки и отладки. Подробности и команды —
  в [dev_env/README.md](dev_env/README.md).
- **[demo/](demo/)** — предсобранные образы, можно перенести на
  изолированный хост одним архивом. Подробности и сборка образов —
  в [demo/README.md](demo/README.md).
