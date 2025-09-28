FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and main.go
COPY go.mod ./
COPY main.go ./

# Download dependencies and create go.sum
RUN go mod tidy

# Build the application
RUN go build -o school-chat main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy the built binary
COPY --from=builder /app/school-chat .

EXPOSE 8080

CMD ["./school-chat"]