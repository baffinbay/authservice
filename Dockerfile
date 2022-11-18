FROM golang:1.19-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o authservice .

FROM alpine

COPY tmpl ./app/tmpl/.

COPY --from=builder /app/authservice ./app/authservice

WORKDIR /app

ENTRYPOINT ["/app/authservice"]
