.PHONY: format lint typecheck test security build verify

format:
	cd cli && gofmt -w *.go

lint:
	cd backend && ruff check app tests
	cd frontend && npm run lint

typecheck:
	cd backend && mypy app
	cd frontend && npm run typecheck

test:
	cd backend && pytest
	cd cli && go test ./...

security:
	powershell -NoProfile -Command "if (rg -n --glob '!README.md' --glob '!THREAT_MODEL.md' --glob '!SECURITY.md' '(?i)(console\.log.*(secret|token)|logger\..*(secret|token)|Access-Control-Allow-Origin:\s*\*)' .) { exit 1 }"

build:
	cd backend && python -m build
	cd frontend && npm run build
	cd cli && go build ./...

verify: format lint typecheck test security build

