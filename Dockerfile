# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY go.sum ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o github-webhook-validator .

# Final stage — scratch for minimal image
FROM scratch

COPY --from=builder /app/github-webhook-validator /github-webhook-validator

EXPOSE 8080
ENTRYPOINT ["/github-webhook-validator"]