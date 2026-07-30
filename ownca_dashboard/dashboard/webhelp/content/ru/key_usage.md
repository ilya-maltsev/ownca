# Key Usage и Extended Key Usage

Эти расширения определяют, как может (и должен) использоваться
открытый ключ из сертификата.

## Key Usage

Битовая маска. Каждый бит соответствует одному типу операции.

| Бит | Имя | Назначение |
|---|---|---|
| 0 | `digitalSignature` | Подпись данных, не относящаяся к подписанию сертификатов или CRL: TLS-handshake, аутентификация, JWT. |
| 1 | `nonRepudiation` (= `contentCommitment`) | Юридически значимая подпись (электронная подпись документов). |
| 2 | `keyEncipherment` | Шифрование симметричного ключа (key transport). Используется в RSA-key-exchange TLS. |
| 3 | `dataEncipherment` | Прямое шифрование пользовательских данных открытым ключом. На практике редко включается. |
| 4 | `keyAgreement` | Выработка общего секрета (Diffie–Hellman, ECDH, ГОСТ VKO). |
| 5 | `keyCertSign` | Подпись сертификатов. **Только для УЦ.** |
| 6 | `cRLSign` | Подпись CRL. **Только для УЦ или выделенного CRL-signer.** |
| 7 | `encipherOnly` | Уточнение к `keyAgreement`: только шифрование (только если бит `keyAgreement` тоже выставлен). |
| 8 | `decipherOnly` | Аналогично — только расшифрование. |

> Расширение Key Usage **обязано** быть `critical=TRUE`, если
> сертификат имеет неоднозначное назначение.

### Типичные сочетания

| Применение | Биты |
|---|---|
| TLS-сервер (RSA) | `digitalSignature`, `keyEncipherment` |
| TLS-сервер (ECDSA / ГОСТ) | `digitalSignature` (+`keyAgreement`) |
| TLS-клиент | `digitalSignature` |
| Подпись e-mail (S/MIME signing) | `digitalSignature`, `nonRepudiation` |
| Шифрование e-mail (S/MIME encryption) | `keyEncipherment` |
| Подпись кода | `digitalSignature` |
| УЦ | `keyCertSign`, `cRLSign` |

## Extended Key Usage

Список OID-ов, описывающих прикладные назначения. В отличие от Key
Usage, EKU обычно идёт `critical=FALSE`, но клиенты (особенно
браузеры для TLS-сервера) проверяют его обязательно.

### Типовые OID-ы

| OID | Имя | Применение |
|---|---|---|
| `1.3.6.1.5.5.7.3.1` | `id-kp-serverAuth` | TLS Server Authentication |
| `1.3.6.1.5.5.7.3.2` | `id-kp-clientAuth` | TLS Client Authentication |
| `1.3.6.1.5.5.7.3.3` | `id-kp-codeSigning` | Подпись кода |
| `1.3.6.1.5.5.7.3.4` | `id-kp-emailProtection` | S/MIME |
| `1.3.6.1.5.5.7.3.8` | `id-kp-timeStamping` | Time-Stamping Authority |
| `1.3.6.1.5.5.7.3.9` | `id-kp-OCSPSigning` | OCSP-респондер |
| `2.5.29.37.0` | `anyExtendedKeyUsage` | Любое EKU |
| `1.3.6.1.4.1.311.10.3.4` | Microsoft EFS | Шифрование файлов |
| `1.2.643.2.2.34.6` | ГОСТ — TLS-сервер | Используется в РФ-ориентированных сертификатах |

### Сочетание Key Usage и Extended Key Usage

При path validation клиент проверяет **пересечение** заявленных
назначений. Например:

* TLS-сервер: KU должен включать `digitalSignature`, EKU — `serverAuth`.
* Если сертификат содержит EKU без `serverAuth`, использование в роли
  TLS-сервера ОТВЕРГАЕТСЯ независимо от KU.

## Где это настраивается в OwnCA

* В каждом [профиле сертификата](cert_profiles.md) — флажки KU и
  список EKU OID-ов. Когда форма [Выпуск произвольного
  сертификата](custom_cert_issue.md) использует профиль, его строки
  KU и EKU имеют приоритет; свободные KU/EKU-элементы формы для
  этих атрибутов игнорируются (но применяются к другим
  расширениям, которые профиль не задаёт). В free-form режиме (без
  профиля) используются именно значения формы.

## Связанные разделы

* [Структура X.509-сертификата](x509_overview.md)

