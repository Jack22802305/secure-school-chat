FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy the subdirectory contents
COPY "Messaging platform test v2/" ./

# Download dependencies
RUN go mod tidy

# Build the application
RUN go build -o school-chat school_secure_server.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Copy the built binary
COPY --from=builder /app/school-chat .

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

CMD ["./school-chat"]