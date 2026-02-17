FROM golang:1.21-alpine AS builder

# Install required packages
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o flan-go-scan ./cmd/flan-go-scan

FROM alpine:latest

RUN apk --no-cache add ca-certificates nmap nmap-scripts

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/flan-go-scan .
COPY --from=builder /app/config ./config
COPY --from=builder /app/ips.txt .

# Create a simple HTTP server wrapper
COPY server.go .

EXPOSE 8080

CMD ["./server"]
