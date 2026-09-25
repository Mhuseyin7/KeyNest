# KeyNest

> Self-hosted application & infrastructure secrets manager — unsafe `.env` paylaşımını güvenli bir workflow ile değiştirmek için tasarlanmıştır.

**KeyNest**, [muhammedkoca.com.tr](https://muhammedkoca.com.tr) tarafından geliştirilen açık kaynaklı bir security software projesidir. Personal password manager değildir; developer ekiplerinin `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET` ve `API_KEY` gibi application secrets değerlerini **Organization → Project → Environment** yapısında güvenle yönetmesine yardımcı olur.

## Neden KeyNest?

`.env` dosyalarını chat uygulamalarında, e-posta ile veya repository dışında kontrolsüz paylaşmak; secret leak, yanlış environment kullanımı ve erişim denetimi sorunlarına yol açar. KeyNest’in hedefi, authorized kullanıcıların veya CI/service account’ların yalnızca ihtiyaç duyduğu secret’lara erişmesini sağlamaktır.

```bash
keynest run --environment <environment-id> -- node server.js
```

CLI, authorized değerleri HTTPS üzerinden alır ve yalnızca child process environment’ına inject eder. Otomatik plaintext `.env` dosyası oluşturmaz.

## Security yaklaşımı

- Secret plaintext PostgreSQL’de tutulmaz; secret values AES-256-GCM ile encrypted olarak saklanır.
- Her secret version için fresh Data Encryption Key (DEK) ve unique nonce üretilir.
- DEK, database dışında sağlanan Master Key ile wrapped edilir. Master Key asla database içinde saklanmaz.
- Password hash işlemleri Argon2id ile yapılır.
- Service token’lar random, scoped, expiring ve revocable’dır; yalnızca hash değerleri saklanır ve plaintext token sadece bir kez gösterilir.
- List API’leri secret value veya ciphertext döndürmez. Value erişimi ayrı, permission-controlled endpoint’lerden yapılır.
- Audit log’lar secret value veya character-level diff içermez.
- Restrictive CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, frame protection, CORS allowlist ve CSRF protection uygulanır.

Detaylı security değerlendirmesi için [THREAT_MODEL.md](THREAT_MODEL.md), deployment sorumlulukları için [SECURITY.md](SECURITY.md), key/backup recovery için [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) dosyalarını mutlaka okuyun.

## Architecture

| Katman | Technology | Sorumluluk |
|---|---|---|
| API | FastAPI + PostgreSQL | Authentication, authorization, encryption, secret versioning, audit |
| CLI | Go | Authorized secret fetch ve process-only environment injection |
| Dashboard | Next.js + React + TypeScript | Masked secret management interface |
| Deployment | Docker Compose | Self-hosted local / server deployment |

## Repository yapısı

```text
backend/       FastAPI API, crypto, authorization ve database models
cli/           Go CLI
frontend/      Next.js dashboard
infra/         Runtime secret deployment notları
THREAT_MODEL.md
SECURITY.md
DISASTER_RECOVERY.md
```

## Quick start

> Production deployment öncesinde [SECURITY.md](SECURITY.md) dokümanını eksiksiz uygulayın. Default admin, default JWT secret veya default encryption key yoktur.

### 1. Runtime secrets oluşturun

`infra/secrets/README.md` içindeki açıklamaya göre aşağıdaki dosyaları oluşturun. Bu dosyalar `.gitignore` ve `.dockerignore` ile korunur; yine de source control’e eklemeyin.

```text
infra/secrets/postgres_password
infra/secrets/database_url
infra/secrets/master_key
infra/secrets/session_secret
```

`master_key`, URL-safe Base64 biçiminde **tam 32 random byte** olmalıdır. Örnek placeholder kullanmayın.

### 2. Stack’i başlatın

```bash
docker compose up --build
```

Production’da API’yi trusted reverse proxy arkasında TLS ile yayınlayın ve `KEYNEST_PUBLIC_ORIGIN` değerini gerçek HTTPS origin olarak ayarlayın.

### 3. Project ve environment oluşturun

Dashboard üzerinden organization, project ve `Development` environment oluşturun. Ardından secret key’leri ekleyin:

```text
DATABASE_URL
REDIS_URL
JWT_SECRET
API_KEY
```

Values default olarak masked görünür. Reveal işlemi explicit ve audited bir action’dır.

### 4. CLI ile process çalıştırın

Mevcut CLI flow, scoped service token kullanır:

```bash
keynest login --server https://keynest.example.com --token knst_...
keynest run --environment <environment-id> -- node server.js
```

Child process gerekli environment variable’ları alır; `.env` yazılmaz. Process exit code korunur ve Ctrl+C / termination signal child process’e iletilir.

## Permissions

KeyNest, role’ların yanında granular permission model kullanır:

```text
secret:list_names
secret:read_values
secret:create
secret:update
secret:delete
secret:export
token:create
token:revoke
audit:read
member:manage
```

Bir kullanıcı secret key adını görebilir, ancak value erişimine sahip olmayabilir. Organization isolation, membership ve permission check’leri API tarafında enforce edilir.

## Secret versioning

Her value değişikliği yeni bir immutable version oluşturur:

```text
DATABASE_URL
├── v1
├── v2
└── v3  ← active
```

Audit kaydı yalnızca `Secret value changed` ve version metadata bilgisini saklar; secret content veya value diff saklamaz.

## CLI ve OS visibility notu

KeyNest `.env` yazmaz, ancak hiçbir software child process environment’ını OS seviyesinde tamamen görünmez yapamaz. Sufficient OS privilege sahibi kullanıcılar, debugger’lar, core dump tools veya process inspection araçları environment variable’lara erişebilir. Workload’ları least-privilege account’larla çalıştırın, crash dump policy’lerini gözden geçirin ve full environment loglamayın.

## Development ve quality checks

CI pipeline aşağıdaki kontrolleri çalıştırır:

```bash
make format
make lint
make typecheck
make test
make security
make build
```

Test suite crypto envelope workflow, nonce generation, password/token hashing, `.env` parser ve secret list endpoint’in value/ciphertext sızdırmama invariant’larını kapsar. CI ayrıca Linux, macOS ve Windows için CLI binary release/checksum workflow içerir.

## Project status

Bu repository security-first MVP foundation olarak geliştirilmiştir. Public production release öncesinde bağımsız security review, durable rate-limit store, versioned database migration workflow, complete MFA/recovery/password-reset flow, browser device authorization ve full dashboard workflow’larının tamamlanması gerekir.

## Contributing

Contribution’lar memnuniyetle karşılanır. Gerçek secret, token, `.env`, production metadata, database dump veya credential içeren commit/issue açmayın. Detaylar için [CONTRIBUTING.md](CONTRIBUTING.md) sayfasına bakın.

Security vulnerability bildirimi için public issue açmayın; [SECURITY.md](SECURITY.md) politikasını kullanın.

## License

Bu proje [MIT License](LICENSE) ile lisanslanmıştır.

---

Made with security in mind by [muhammedkoca.com.tr](https://muhammedkoca.com.tr) · Open source software for safer application secret workflows.
