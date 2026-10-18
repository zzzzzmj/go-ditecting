.PHONY: run test cover vet fmt docker-up docker-down demo

run:
	go run ./cmd/api

test:
	go test ./...

cover:
	go test -race -coverprofile=coverage.out ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

demo:
	curl -X POST http://localhost:8080/api/v1/demo/generate -H "Authorization: Bearer $$TOKEN"

