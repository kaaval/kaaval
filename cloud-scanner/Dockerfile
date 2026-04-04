FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o scanner ./cmd/scanner

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/scanner /usr/local/bin/argus-scanner
ENTRYPOINT ["argus-scanner"]
