FROM golang:1.25.4-alpine

WORKDIR /server

COPY . .

RUN go build -o ./server ./cmd/codesanad/main.go
RUN chmod +x ./server

EXPOSE 8080

CMD ["./server"]