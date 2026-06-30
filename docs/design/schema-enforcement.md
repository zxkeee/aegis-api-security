# Design: Schema Enforcement (positive security)

> Статус: **v1 реализован (стадии 1–3)**. Парсер схем (`discovery/schema.go`),
> валидатор (`discovery/schema_validate.go`), middleware
> (`middleware/schema.go`), wiring в `internal/gateway`. Источник правды по
> объёму и решениям. Связано с ROADMAP B2 и «Protect» в `docs/PRODUCT.md`.
>
> Источник контракта в v1 — **config-level спека** (`discovery.spec_path`),
> парсится при сборке цепочки (обновляется на hot-reload). Per-tenant
> uploaded-спека (та, что у drift в PG) пока **не** enforce-ится — следующий шаг.

## Зачем

Сигнатурный WAF — negative security («блокируй то, что выглядит как атака»).
Schema enforcement — **positive security**: «пропускай только то, что соответствует
документированному контракту API, остальное отклоняй». Это killer-фича класса
Imperva/Salt: закрывает разом

- **API6 Mass Assignment** — клиент шлёт поля, которых нет в схеме
  (`additionalProperties: false` ⇒ reject недокументированных полей);
- значительную часть инъекций и type-confusion (строка вместо integer, и т.п.);
- **API8 Misconfiguration** через расхождение «контракт vs реальный приём».

Опирается на уже готовый dependency-free парсер OpenAPI (`discovery.ParseSpec`)
и канонизацию путей (`canonicalSpecPath`), которые сейчас используются для drift.

## Объём v1

**Валидируем входящий запрос против документированной операции (METHOD+template):**

1. **Параметры** (`query` / `path`): обязательность (`required`), тип
   (`integer`/`number`/`boolean`/`string`/`array`), членство в `enum`.
2. **JSON-тело** (`application/json`): обязательные свойства (`required`), типы
   свойств, `enum`, и — главное — `additionalProperties: false` ⇒ отклонять
   недокументированные поля (anti-mass-assignment).
3. **`$ref`-резолвинг** на `#/components/schemas/*` (OpenAPI 3) и `#/definitions/*`
   (Swagger 2) с защитой от циклов, одноуровнево вглубь по необходимости.

**НЕ в v1 (осознанно):** `allOf/oneOf/anyOf`, форматы (`date`/`email`/regex
`pattern`), `minLength`/`maximum` и прочие ограничения, не-JSON тела
(form/multipart), response-валидация. Добавим итеративно — фиксируем как
ограничения, чтобы не переобещать.

## Поведение и конфиг

Новый блок `security.schema`:

```yaml
security:
  schema:
    enabled: true
    mode: monitor   # monitor | block
    fail_open: true # нераспарсенная схема/неизвестная операция ⇒ пропускать
```

- **mode=monitor** — нарушения логируются + форензика + метрика, запрос проходит
  (безопасный rollout, сбор FP перед включением блока).
- **mode=block** — нарушение ⇒ `422 Unprocessable Entity` с машинным списком
  нарушений (поле, причина), запись в форензику.
- **Неизвестная операция** (нет в спеке): по умолчанию **fail-open** (не наша
  забота — это про undocumented endpoints, их ловит drift/findings). Опционально
  позже: strict-режим «нет в спеке ⇒ reject».
- Источник спеки — тот же, что у drift: per-tenant спека (PG, с RLS) с фолбэком
  на `discovery.spec_path`. Enforcement читает активную спеку per-tenant.

## Размещение в цепочке

После `Auth` и до `proxy` — на одном уровне с `AbuseDetection`/`DLP` (внутри
периметра, видит финальный распарсенный путь). Тело читается с bounded-буфером
(как DLP: cap, при превышении — fail-open для этого запроса, без OOM) и
восстанавливается (`io.NopCloser`) для проксирования.

## Стадии реализации

1. **Парсер схем** (`discovery/schema.go`): расширить `Spec` картой
   `opSchemas[METHOD template] → OpSchema{Params, Body}`; `$ref`-резолвер;
   юнит-тесты на OpenAPI3 + Swagger2 + `$ref` + циклы. ← начинаем здесь.
2. **Валидатор** (`discovery/schema_validate.go`): чистая функция
   `Validate(op, params, body) []Violation`; таблично-тестируемая.
3. **Middleware** (`middleware/schema.go`): match операции, bounded body,
   monitor/block, форензика, метрика; конфиг + валидация; место в цепочке.
4. **Wiring + доки**: прокинуть активную спеку per-tenant, обновить ROADMAP
   (B2 → schema enforcement done) и `RELEASE-CHECKLIST`.
