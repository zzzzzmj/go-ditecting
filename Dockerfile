FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE=api
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${SERVICE}

FROM alpine:3.20
RUN addgroup -S diting && adduser -S -G diting diting
WORKDIR /app
COPY --from=builder /out/app /app/app
USER diting
EXPOSE 8080
ENTRYPOINT ["/app/app"]

