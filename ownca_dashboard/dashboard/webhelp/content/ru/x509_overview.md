# Структура X.509-сертификата

Сертификат X.509 v3 — это подписанная связка открытого ключа с
идентификатором его владельца.

## Основные поля

| Поле | Описание |
|---|---|
| Версия | OwnCA выпускает только v3. |
| Серийный номер | Уникальный в рамках УЦ положительный INTEGER. |
| Issuer / Subject | Distinguished Name УЦ и владельца (CN, O, OU, C, ST, L, …). |
| Validity | Метки времени `notBefore` и `notAfter`. |
| Открытый ключ | Алгоритм и сам ключ. |
| Расширения | Опциональные поля (Key Usage, SAN, точки распространения и т. п.) — только в v3. |

## Расширения

Каждое расширение содержит OID, флаг `critical` и значение. Если
`critical=TRUE`, клиент **обязан** понимать это расширение, иначе
сертификат должен быть отвергнут.

### Стандартные расширения

| OID | Имя |
|---|---|
| `2.5.29.14` | Subject Key Identifier |
| `2.5.29.35` | Authority Key Identifier |
| `2.5.29.15` | Key Usage |
| `2.5.29.32` | Certificate Policies |
| `2.5.29.17` | Subject Alternative Name |
| `2.5.29.19` | Basic Constraints |
| `2.5.29.30` | Name Constraints |
| `2.5.29.36` | Policy Constraints |
| `2.5.29.37` | Extended Key Usage — см. [Key Usage](key_usage.md) |
| `2.5.29.31` | CRL Distribution Points — см. [Distribution points](distribution_points.md) |
| `1.3.6.1.5.5.7.1.1` | Authority Information Access |
| `1.3.6.1.5.5.7.1.11` | Subject Information Access |

## Подпись

Сертификат подписывается закрытым ключом издающего УЦ. Алгоритм
зависит от УЦ — RSA, ECDSA, Ed25519 или ГОСТ (см. [ГОСТ-алгоритмы](gost_algorithms.md)).

## Связанные разделы

* [Key Usage и Extended Key Usage](key_usage.md)
* [Точки распространения](distribution_points.md)
* [ГОСТ-алгоритмы](gost_algorithms.md)
* [Глоссарий](glossary.md)
