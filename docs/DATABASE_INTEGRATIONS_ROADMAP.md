# Roadmap: Carrier-Grade Database Integrations & Offline Feeds

Документ фиксирует стратегический роадмап усиления существующих инструментов сайта (`corpberry.com`) за счет скачиваемых структурированных баз данных, регулярных синков и открытых протоколов, исключая нестабильный live web scraping и HTTP 429 блокировки.

---

## 1. Реализовано (Статус: Done / In Production)

### 1.1 Verified Crawler IP Feeds (`tools/botcheck`)
- Ежедневная фоновая загрузка официальных CIDR JSON-фидов Googlebot, Bingbot и OpenAI с атомарной заменой `atomic.Pointer`.

### 1.2 Extended Disposable Email Sources (`tools/mailtools`)
- Еженедельный синк агрегированных баз (`disposable-email-domains` canonical + Wesbos burner email provider list).

### 1.3 BGP / RPKI Route Origin Validation (`tools/iptools`)
- RFC 6811 RPKI ROA валидатор на основе ежедневного RPKI JSON-дампа Cloudflare с 256-корзинным индексом по первому октету IPv4 ($O(1)$ sub-ms lookup).

### 1.4 Pre-Push Quality & Anti-Patch Gateway
- Автоматический шлюз аудита в `scripts/audit-agent-gate.sh` и `.githooks/pre-push`: блокировка downstream-патчей, проверка DRY/KISS/YAGNI, соответствие тестов и запуск race-тестов по затронутым пакетам.

### 1.5 Threat Intelligence: Tor Exit Node Feed (`tools/iptools`)
- Ежедневный регулярный синк официального Tor Bulk Exit List (`check.torproject.org/torbulkexitlist`) в общую коллекцию `ip_blocklist` с фоновым воркером `RunTorExitSync(ctx)` в `main.go`.

### 1.6 PeeringDB & IXP Connectivity Insights (`tools/iptools`)
- Еженедельный синк PeeringDB snapshot: отображение точек присутствия на IXP, пиринговой политики (`Open`, `Selective`), соотношения трафика и масштаба сети для любого ASN.

### 1.7 DNSSEC Cryptographic Chain Validation (`tools/dnstools`)
- Проверка криптографической цепочки DNSKEY/RRSIG и флага Authenticated Data (AD) без внешних платных API с распознаванием алгоритмов и проверкой Key Tags.

### 1.8 Certificate Transparency Local Cache (`tools/dnstools`)
- Потокобезопасный локальный кеш (`CTCache`) с настраиваемым TTL, снижающий нагрузку на upstream crt.sh и предотвращающий троттлинг.

### 1.9 RFC 7208 SPF Mechanism Evaluator Engine (`tools/mailtools`)
- Локальный анализатор соответствия IP клиента механизмам SPF (`ip4`, `ip6`, `all`) с выдачей стандартных RFC вердиктов (`Pass`, `Fail`, `Softfail`, `Neutral`, `PermError`).

---

## 2. Предложенные фичи в бэклоге (Статус: Backlog / Proposed)

Следующие фичи были предложены для расширения существующих инструментов за счет надежных баз данных и стандартизированных протоколов:

### 2.1 Threat Intelligence & Abuse Feeds
- **Целевой инструмент:** `tools/iptools` и `tools/botcheck`.
- **Источники данных:**
  - **AbuseIPDB Blacklist / FireHOL Level 1 & 2:** регулярный синк списков активных хостов с признаками сканирования и брутфорса.
  - **Tor Exit Nodes List:** официальный почасовой фид узлов выхода Tor (`check.torproject.org/torbulkexitlist`).
  - **OpenVPN / WireGuard / Datacenter Egress CIDRs:** фиды ASN хостинг-провайдеров для маркировки датацентровых прокси.
- **Преимущество:** Обогащение отчета по IP без сторонних API-ключей и лимитов.

### 2.2 PeeringDB & IXP Connectivity Insights
- **Целевой инструмент:** `tools/iptools` (`asn.corpberry.com` / `ip.corpberry.com`).
- **Источники данных:** Еженедельный дамп PeeringDB SQLite / JSON dump.
- **Функционал:**
  - Отображение Internet Exchange Points (IXP), к которым подключена автономная система (ASN).
  - Политика пиринга (Open, Selective, Restrictive) и емкость каналов в точках обмена трафиком.
- **Преимущество:** Превращает простой просмотр ASN в профессиональный сетевой диагностический инструмент операторского уровня.

### 2.3 Extended DNSSEC Validation & Trust Anchor Ledger
- **Целевой инструмент:** `tools/dnstools`.
- **Источники данных:** Корневые Trust Anchors IANA (`root-anchors.xml`), дампы TLD с поддержкой DNSSEC.
- **Функционал:**
  - Полная валидация цепочки доверия (DS -> DNSKEY -> RRSIG) с проверкой криптографических подписей на стороне сервера без внешних платных сервисов.
  - Детектирование алгоритмического устаревания (SHA-1, RSA-1024).

### 2.4 CT Logs (Certificate Transparency) SQLite Dump / Cache
- **Целевой инструмент:** `tools/dnstools` (Subdomain & Certificate Insights).
- **Источники данных:** Агрегированные базы Certificate Transparency или локальный индекс недавних сертификатов для домена.
- **Функционал:** Обнаружение поддоменов через выпуск SSL/TLS сертификатов без активного брутфорса и риска блокировки по IP.

### 2.5 SPF / DMARC Policy Evaluator Engine
- **Целевой инструмент:** `tools/mailtools`.
- **Источники данных:** RFC 7208 / RFC 7489 спецификации с локальным парсером графа директив.
- **Функционал:**
  - Локальный симулятор проверки входящего письма (IP + Sender -> Pass/Fail/Softfail).
  - Детектирование превышения лимита 10 DNS lookups для SPF.
  - Анализ DMARC aggregate reports (`rua`) конфигурации.

---

## 3. Критерии приемки для новых фичей
1. **Только скачиваемые базы/фиды:** Никакого live-скрейпинга HTML страниц, подверженного HTTP 429/403.
2. **Фоновая регулярная синхронизация:** Загрузка по расписанию (cron/worker) с сохранением в локальный кеш/память/Mongo.
3. **Graceful Lifecycle:** Каждый фоновый синк должен реализовывать сигнатуру `Run...Sync(ctx context.Context)` и управляться через `sync.WaitGroup` в `main.go`.
4. **Контроль DRY & Anti-Patch:** Все изменения должны проходить через `scripts/audit-agent-gate.sh`.
