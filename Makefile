.PHONY: run test cover vet fmt migrate-up migrate-version docker-up docker-down demo

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

migrate-up:
	go run ./cmd/migrate up

migrate-version:
	go run ./cmd/migrate version

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

demo:
	curl -X POST http://localhost:8080/api/v1/demo/generate -H "Authorization: Bearer $$TOKEN"

