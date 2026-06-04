FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o backend .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/backend .
EXPOSE 8081
CMD ["./backend"]