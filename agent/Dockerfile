FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kaaval-agent ./cmd/kaaval-agent

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/kaaval-agent /usr/local/bin/kaaval-agent
ENTRYPOINT ["kaaval-agent"]
