# `ownca_capi` — мост OwnCA ⇄ CryptoPro CSP (CAPILite)

Тонкая утилита на C, через которую идёт вся российская криптография УЦ при
включённом сертифицированном провайдере. Python вызывает её через `subprocess` —
ровно так же, как вызывает `openssl`. Ключ УЦ никогда не покидает контейнер
CryptoPro; через границу процесса ходят только DER-байты сертификатов, CRL и
PFX.

Исходник: [`ownca_capi.c`](ownca_capi.c) (один файл, зависимость только от
CAPILite). Вызывающая сторона: [`../dashboard/own_ca.py`](../dashboard/own_ca.py).

**Почему отдельный процесс.** Ключ живёт в контейнере провайдера, и хочется,
чтобы Python физически не мог его увидеть — структурно, а не по договорённости.
openssl и CAPILite не смешиваются: разные модели ключа, ASN.1-энкодеры и
представления DN, так что «дополнять» openssl вызовами CAPI внутри одного
процесса — хрупко. Наконец, `own_ca.py` уже был обёрткой над
`subprocess.run(['openssl', …])`, и мост встал в ту же форму: `_run_capi()`
отличается от `_run()` только именем бинаря.

Следствие: **мост не принимает решений политики**. Он не знает про профили,
режимы выпуска и права операторов — всё это решается в Python до вызова.

---

## 1. Сборка

Собирается только в образе, куда подан дистрибутив CryptoPro (см.
[`dev_env/build.sh`](../../dev_env/build.sh)). Строка сборки — в
[`dev_env/dashboard/Dockerfile`](../../dev_env/dashboard/Dockerfile):

```sh
gcc -DUNIX -DHAVE_LIMITS_H -m64 -DSIZEOF_VOID_P=8 \
    -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp \
    -I/opt/cprocsp/include/asn1c/rtsrc -I/opt/cprocsp/include/asn1data \
    ownca_capi.c -o /opt/ownca/bin/ownca_capi \
    -L/opt/cprocsp/lib/amd64 -lssp -lcapi10 -lcapi20 -lrdrsup
```

Флаги `-DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8` обязательны: без них заголовки
CryptoPro разворачиваются в Windows-вариант типов. `gcc` ставится на время
сборки и вычищается следом. После успешной сборки Dockerfile пишет маркер
`/opt/ownca/.cryptopro_available` — его читает `cryptopro.available()`; нет
маркера, нет и провайдера.

**Отладочная пересборка.** Каталог `ownca_dashboard/` примонтирован в
контейнер, поэтому мост можно перекомпилировать на месте, не пересобирая образ:
поставить в контейнер `gcc libc6-dev` и повторить строку выше по
`/opt/app/capi/ownca_capi.c`. Так проверяют гипотезы; итог обязательно
закрепляется полной пересборкой (`dev_env/build.sh`), иначе первый же
`docker compose up --force-recreate` вернёт бинарь из образа и молча откатит
правку.

---

## 2. Контракт вызова

| | |
|---|---|
| **Успех** | код возврата `0`, одна строка JSON в `stdout` |
| **Ошибка выполнения** | код `1`, диагностика в `stderr` |
| **Ошибка аргументов** | код `2`, текст `usage`/`needs` в `stderr` |

Python (`_run_capi`) считает ненулевой код ошибкой и поднимает `OwnCAError`,
склеивая `stderr` и `stdout` в текст сообщения. Диагностика доходит до оператора
в веб-панели дословно — писать её стоит понятной не только разработчику.

JSON печатается **последней строкой**: вызывающая сторона разбирает
`out.strip().splitlines()[-1]`. Не добавляйте вывод после него.

Все команды, порождающие артефакт, принимают `--out FILE` и пишут туда **DER**.
Преобразованием в PEM занимается Python (`_der_file_to_pem`) — чистый base64,
без единого вызова openssl над ГОСТ-материалом.

---

## 3. Справочник команд

```
ownca_capi <info|paramsets|genkey|gencsr|selfsign|issue|issuecsr|gencrl|exportpfx|importpfx|delcontainer> [опции]
```

### `info`
Проверка живости, без аргументов → `{"shim":"ownca_capi","ok":true}`.

### `paramsets --alg gost2012_256|gost2012_512`
Наборы параметров, которые поддерживает провайдер (`PP_ENUM_SIGNATUREOID`), —
чтобы форма выпуска не предлагала набор, который будет отвергнут.
→ `{"alg":"gost2012_256","oids":["1.2.643.2.2.35.1", …],"ok":true}`

### `genkey --container ИМЯ [--alg ...] [--paramset A|B|C|XA|XB]`
Создаёт пару `AT_SIGNATURE` в контейнере. Флаг `CRYPT_EXPORTABLE` обязателен:
без него `PFXExportCertStoreEx` молча отдаст PFX без ключа.

Набор параметров ставится **на провайдере до генерации**
(`CryptSetProvParam(PP_SIGNATUREOID)` → `CryptGenKey`); отложенный идиом из
документации (`CRYPT_PREGEN` + `KP_SIGNATUREOID` + `KP_X`) для `AT_SIGNATURE` в
этом CSP не работает — см. §7. Неизвестное имя набора отвергается с кодом `2`,
контейнер при этом не создаётся. Если ключ уже есть (`NTE_EXISTS`), команда
успешна и ничего не трогает — вызов идемпотентен.

### `gencsr --container ИМЯ --subject DN [--alg ...] --out FILE`
PKCS#10 для ключа из контейнера, подписанный им же. Выпуску не нужна (`issue`
берёт открытый ключ прямо из контейнера) — существует ради паритета артефактов
на диске, чтобы у сертификата с серверной генерацией был тот же `csr.pem`, что
и на openssl-пути. Python вызывает её best-effort: если шим старый и команды не
знает, выпуск не падает.

### `selfsign --container ИМЯ --subject DN --out FILE [--days N] [--serial HEX] [--alg ...] [--extspec FILE]`
Самоподписанный корневой УЦ. `--days` по умолчанию `3650`.

### `issue --container CA --subject-container SUBJ --subject DN --issuer DN --out FILE [--days N] [--serial HEX] [--alg CA_ALG] [--subject-alg SUBJ_ALG] [--extspec FILE]`
Выпуск по ключу в контейнере субъекта: промежуточный УЦ или конечный сертификат
с серверной генерацией. `--days` по умолчанию `365`. `--alg` — алгоритм **УЦ**
(определяет OID подписи и тип провайдера), `--subject-alg` — алгоритм субъекта;
они могут различаться (256 против 512).

### `issuecsr --container CA --csr FILE --issuer DN --out FILE [--subject DN] [--days N] [--serial HEX] [--alg CA_ALG] [--extspec FILE]`
Выпуск по внешнему PKCS#10 (DER): декодирование запроса → **проверка его
самоподписи** провайдером, подобранным по алгоритму ключа из самого запроса (а
не по алгоритму УЦ) → подпись сертификата ключом УЦ.

Subject DN по умолчанию берётся из запроса **побайтно** — это важно для
стабильности цепочки; `--subject` его переопределяет.

### `gencrl --container CA --issuer DN --out FILE [--days N] [--crlnumber HEX] [--revoked FILE] [--alg ...]`
Подпись CRL ключом УЦ. `--days` по умолчанию `7`, но Python всегда передаёт
значение явно (`_ca_crl_days`). `thisUpdate` ставится на 5 минут назад — запас
на расхождение часов у потребителя. Формат `--revoked` — в §5.

### `exportpfx --container ИМЯ --cert FILE [--password PW] [--chain FILE]... [--alg ...] --out FILE`
`PFXExportCertStoreEx`: сертификат + ключ из контейнера в PFX. `--chain`
повторяемый, добавляет сертификаты **без ключа** (родительская цепочка).
Шифрование — штатное для CryptoPro, управлять им нельзя: `pvReserved`
зарезервирован, набор `dwFlags` фиксирован. Отсюда ограничение — ни ТК-26, ни
ГОСТ-наборы PBE на этом пути недоступны.

### `importpfx --pfx FILE [--password PW] --out FILE`
`PFXIsPFXBlob` → `PFXVerifyPassword` → `PFXImportCertStore`. Закрытый ключ
попадает прямо в контейнер и никогда не появляется на диске; в `--out` пишется
DER сертификата, владеющего ключом.

```json
{"out":"...","container":"pfx-<guid>","provtype":80,"subject":"CN=..., O=...","ok":true}
```

Имя контейнера **назначает CryptoPro**, а не мы. Python обязан сохранить его из
этого JSON (`cas/<uuid>/backend`) — вычислить по своему шаблону нельзя.

### `delcontainer --container ИМЯ [--alg ...]`
`CryptAcquireContextA(..., CRYPT_DELETEKEYSET)` — удаляет контейнер ключа.
Вызывается, когда УЦ или сертификат удаляют, а также при откате неудавшегося
создания: каталог на диске уносит `shutil.rmtree`, но ключ лежит в хранилище
CSP, вне тома с данными.

```json
{"container":"ownca_ca_...","provtype":80,"deleted":true,"ok":true}
```

Тип провайдера входит в идентичность контейнера, а импортированный контейнер
несёт тот, который выбрал `PFXImportCertStore`, поэтому `--alg` — только
подсказка: перебираются оба типа ГОСТ. Отсутствующий контейнер
(`NTE_BAD_KEYSET`) — это `deleted:false` и код возврата 0: очистка запускается и
там, где контейнер мог не создаваться, и должна оставаться идемпотентной. После
успеха дескриптор недействителен, освобождать его нельзя.

---

## 4. Формат `extspec`

Файл `ключ=значение`, по одной паре на строку; `#` — комментарий. Неизвестные
ключи молча игнорируются, поэтому **добавление ключа обратно совместимо**, а
опечатка в имени не диагностируется — сверяйтесь с `ext=N` в JSON, сколько
расширений реально закодировано. Повторяемые ключи накапливаются (до `MAX_LIST`
= 32), всего расширений — не больше `MAX_EXT` = 16.

| Ключ | Значение | Расширение |
|---|---|---|
| `bc` | `1` — включить | basicConstraints |
| `bc_ca` | `0`/`1` | `CA:` |
| `bc_critical` | `0`/`1` | флаг critical |
| `bc_pathlen` | целое, `<0` — не задавать | `pathlen:` |
| `ku_hex` | биты KeyUsage в hex | keyUsage |
| `ku_unused` | число неиспользуемых бит в последнем байте | |
| `ku_critical` | `0`/`1` | |
| `eku` | OID; **повторяемый** | extendedKeyUsage |
| `eku_critical` | `0`/`1` | |
| `ski` | `1` | subjectKeyIdentifier (ГОСТ-хеш открытого ключа) |
| `aki` | `1` | authorityKeyIdentifier (keyid = SKI ключа УЦ) |
| `aki_issuer_dn` | X.500 DN | authorityCertIssuer (directoryName) |
| `aki_issuer_serial` | hex | authorityCertSerialNumber |
| `san_dns` `san_email` `san_uri` | значение; повторяемые | subjectAltName |
| `san_ip` | **hex-октеты**, не точечная запись; повторяемый | |
| `cdp` | URI; повторяемый | crlDistributionPoints |
| `aia_ca` / `aia_ocsp` | URI; повторяемые | AIA: caIssuers / OCSP |
| `sia_repo` | URI; повторяемый | subjectInfoAccess, caRepository |
| `freshest_crl` | URI; повторяемый | freshestCRL |
| `ian_dns` `ian_email` `ian_uri` `ian_ip` | как `san_*` | issuerAltName |

`aki_issuer_*` имеют смысл только вместе с `aki=1` — они соответствуют
openssl-записи `authorityKeyIdentifier = keyid:always, issuer:always` и
идентифицируют **сертификат УЦ**: DN его издателя и его серийный номер.

Пример — промежуточный УЦ со всеми указателями:

```
bc=1
bc_ca=1
bc_critical=1
bc_pathlen=0
ku_hex=06
ku_unused=1
ku_critical=1
ski=1
aki=1
cdp=http://pki.example/root.crl
aia_ca=http://pki.example/root.crt
aia_ocsp=http://ocsp.example/
sia_repo=http://pki.example/repo/
freshest_crl=http://pki.example/delta.crl
ian_dns=ca.example
ian_ip=0a000001
```

---

## 5. Формат `--revoked`

По строке на отозванный сертификат: `serialhex[,unixtime[,reasoncode]]`, где
`serialhex` — big-endian hex чётной длины, `unixtime` — время отзыва (по
умолчанию текущее), `reasoncode` — код RFC 5280 §5.3.1 (`1` = keyCompromise,
`4` = superseded, …).

**Отсутствие третьего поля означает «причина не записана»** — расширение
`reasonCode` тогда не добавляется вовсе. Это осознанно повторяет поведение
openssl при отзыве без `-crl_reason`: не надо утверждать `unspecified` за
оператора. Строки с `#` и нераспознанные серийники пропускаются.

---

## 6. Соглашения о данных

**Серийные номера.** На вход — big-endian hex; внутри `parse_serial_le`
переворачивает байты (`CRYPT_INTEGER_BLOB` в CryptoAPI little-endian). Python
генерирует серийник положительным ASN.1 INTEGER (старший бит снят) и ненулевым.

**DN.** `CertStrToNameA` с `CERT_X500_NAME_STR`, то есть форма `CN=x, O=y`;
openssl-форма `/CN=x/O=y` **не принимается** — Python конвертирует
(`_openssl_subj_to_x500`). Для стабильности цепочки точная строка DN
записывается на диск при создании УЦ (`subject_x500`, `issuer_x500`), а не
восстанавливается разбором сертификата.

**Имена контейнеров.** Созданные нами — `ownca_ca_<hex>` / `ownca_crt_<hex>`
(без дефисов: HDIMAGE их не любит). Импортированные — как назвал CryptoPro.
Авторитетный источник всегда `cas/<uuid>/backend`, а не шаблон имени.

**Алгоритмы.** `gost2012_256` → провайдер 80, `gost2012_512` → 81. От этого
зависят OID подписи, хеш для SKI/AKI и доступный список наборов параметров.

**Что делает Python вокруг** (и что **не** должно переезжать в C): выбор
провайдера по маркеру, валидация набора параметров по списку провайдера, отказ
по некодируемым расширениям (`capilite_unsupported_ext_keys` — один источник и
для отказа, и для предупреждения в интерфейсе), разбор `issuerAltName` по типам,
конвертация DER→PEM, счётчик CRL, хранение метаданных УЦ.

---

## 7. Коды ошибок, встреченные на практике

| Код | Имя | Причина |
|---|---|---|
| `0x80090022` | `NTE_SILENT_CONTEXT` | Пуст пул гаммы ДСЧ: провайдер пытается запросить энтропию диалогом, а контекст открыт с `CRYPT_SILENT`. Лечится загрузкой гаммы через панель обслуживания. |
| `0x80090009` | `NTE_BAD_FLAGS` | `CryptGenKey` с `CRYPT_PREGEN` для `AT_SIGNATURE`: отложенная генерация в этом CSP не поддерживается — набор параметров ставится через `PP_SIGNATUREOID` до генерации. |
| `0x8009000A` | `NTE_BAD_TYPE` | `CryptSetKeyParam(KP_SIGNATUREOID)` на уже сгенерированном ключе. Поздно: параметры выбираются до генерации. |
| `NTE_EXISTS` | | Контейнер уже содержит ключ. `genkey` считает это успехом. |

---

## 8. Как расширять и как проверять

**Добавить расширение X.509:** поле в `ExtSpec` + разбор в `parse_extspec`
(ключ не должен пересекаться с существующими префиксами) → блок кодирования в
`build_extensions` по образцу соседнего (следите за `MAX_EXT`) → освобождение
памяти (`rgExt[i].Value.pbData` освобождает вызывающий, промежуточное — вы сами
в том же блоке) → на стороне Python: параметр `_write_extspec`, передача из
`CertSpec`/`CASpec` и **удаление ключа из отказа** `_CAPI_SUPPORTED_EXT_KEYS`
→ тест на строку extspec плюс проверка на живом CSP.

**Добавить подкоманду:** функция `cmd_*` рядом с родственными (порядок в файле
важен — статические функции определяются до использования), строка в `main`,
строка в `usage`, запись в шапке файла.

**Не добавляйте** в мост логику политики и умолчания, которые уже есть в
Python: две правды рано или поздно разойдутся, и разойдутся молча.

**Проверка.** Автотесты Python (`dashboard/tests/test_cryptopro.py`) вызовы
моста **подменяют**: они проверяют аргументы и разбор вывода, но не сам
CAPILite — тесты должны идти и на образе без CryptoPro. Поэтому C-часть
проверяется вручную на образе с провайдером:

```sh
D='docker compose -f dev_env/docker-compose.yml exec -T gh_ownca_dev_dashboard'
# гамма (иначе NTE_SILENT_CONTEXT)
$D python -c "
import django,os; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); django.setup()
from dashboard import cryptopro; cryptopro.write_gamma(cryptopro.generate_gamma(500), mode='replace')"

$D sh -lc '
set -e
W=/tmp/chk; rm -rf $W; mkdir -p $W
printf "bc=1\nbc_ca=1\nbc_critical=1\nku_hex=06\nku_unused=1\nku_critical=1\nski=1\naki=1\n" > $W/ext.txt
/opt/ownca/bin/ownca_capi genkey  --container chk_ca --alg gost2012_256 --paramset A
/opt/ownca/bin/ownca_capi selfsign --container chk_ca --subject "CN=Chk CA, O=OwnCA" \
    --days 365 --serial 4011223344556677 --alg gost2012_256 --extspec $W/ext.txt --out $W/ca.der
openssl x509 -inform DER -in $W/ca.der -noout -text | head -30
/opt/cprocsp/bin/amd64/csptest -keyset -deletekeyset -container chk_ca'
```

Результат проверяйте **сторонним разбором** (`openssl x509 -text`,
`openssl crl -text`, `openssl req -verify`), а не выводом самого моста:
`{"ok":true}` означает лишь, что CAPILite не вернул ошибку, но ничего не
говорит о том, что закодировано именно нужное. Контейнеры после проверок
удаляйте — они переживают пересборку образа, потому что
`/var/opt/cprocsp/keys` это том.

---

## 9. Ограничения

Полный перечень — в веб-справке (**Система → Криптопровайдер CryptoPro CSP**)
и в [корневом README](../../README.md#ограничения-криптопровайдера-cryptopro).
Коротко, в терминах моста:

* PBE при экспорте PFX не управляется — только штатное шифрование CryptoPro;
* набор кодируемых расширений закрыт (§4); всё за его пределами Python отвергает
  **до** вызова моста;
* `otherName` в SAN и `dirName`/`RID` в issuerAltName не кодируются;
* закрытый ключ не выдаётся наружу иначе как в составе PFX.
