FROM golang:1.23-alpine AS builder
WORKDIR /app
# sqlite3 needs gcc
RUN apk add --no-cache gcc musl-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o backend .

FROM alpine:latest
WORKDIR /app
# create data folder for sqlite
RUN mkdir -p /app/data
COPY --from=builder /app/backend .
EXPOSE 8081
CMD ["./backend"]