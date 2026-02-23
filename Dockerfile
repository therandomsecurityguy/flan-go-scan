FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o flan ./cmd/flan

FROM cgr.dev/chainguard/static:latest

COPY --from=builder /app/flan /flan
COPY --from=builder /app/config /config
COPY --from=builder /app/ips.txt /ips.txt

ENTRYPOINT ["/flan", "-c=/config/config.yaml"]
