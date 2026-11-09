# Roadmap: Carrier-Grade Database Integrations & Offline Feeds

Документ фиксирует стратегический роадмап усиления существующих инструментов сайта (`corpberry.com`) за счет скачиваемых структурированных баз данных, регулярных синков и открытых протоколов, исключая нестабильный live web scraping и HTTP 429 блокировки.

---

## 1. Реализовано (Статус: Done / In Production)

### 1.1 Verified Crawler IP Feeds (`tools/botcheck`)
- **Проблема:** Поисковые краулеры (Googlebot, Bingbot, OpenAI SearchBot) делят инфраструктурные ASN с публичными облаками (Google Cloud, Microsoft Azure). Проверка по одному ASN уязвима к спуфингу.
- **Решение:** Ежедневная фоновая загрузка официальных CIDR JSON-фидов Googlebot, Bingbot и OpenAI.
- **Реализация:** Потоковый парсинг в `tools/botcheck/crawler_ips.go`, атомарная замена `atomic.Pointer[map[string][]netip.Prefix]`, интеграция в `goodbots.go`.

### 1.2 Extended Disposable Email Sources (`tools/mailtools`)
- **Проблема:** Одноразовые домены почты быстро ротируются, одного источника недостаточно для качественного детектирования.
- **Решение:** Еженедельный синк агрегированных баз (`disposable-email-domains` canonical + Wesbos burner email provider list).
- **Реализация:** Оптимизированный фоновый воркер `tools/mailtools/worker.go`, объединение списков без аллокационного оверхеда.

### 1.3 BGP / RPKI Route Origin Validation (`tools/iptools`)
- **Проблема:** Ошибки конфигурации BGP и BGP hijacking приводят к перехвату трафика. Простые WHOIS/ASN проверки не показывают легитимность маршрутизации.
- **Решение:** Полноценный RFC 6811 RPKI ROA валидатор на основе ежедневного RPKI JSON-дампа Cloudflare (декомпрессия gzip на лету).
- **Реализация:** 256-корзинный индекс по первому октету IPv4 в `tools/iptools/rpki.go` (субмиллисекундный поиск среди ~450k ROA), поддержка multi-homed ROA, интеграция в UI `tools/iptools/templates/result.html`.

### 1.4 Pre-Push Quality & Anti-Patch Gateway
- **Решение:** Скрипт `scripts/audit-agent-gate.sh` и интеграция в `.githooks/pre-push`.
- **Контроль:** Блокировка пуша при обнаружении downstream-патчей, проверка соблюдения DRY/KISS/YAGNI, соответствие тестового покрытия и запуск race-тестов по затронутым пакетам.

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
