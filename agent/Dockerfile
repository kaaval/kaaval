FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o argus-agent ./cmd/argus-agent

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/argus-agent /usr/local/bin/argus-agent
ENTRYPOINT ["argus-agent"]
