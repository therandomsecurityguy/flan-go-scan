FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o flan-go-scan ./cmd/flan-go-scan

FROM cgr.dev/chainguard/static:latest

COPY --from=builder /app/flan-go-scan /flan-go-scan
COPY --from=builder /app/config /config
COPY --from=builder /app/ips.txt /ips.txt

ENTRYPOINT ["/flan-go-scan", "-config=/config/config.yaml"]
