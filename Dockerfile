FROM golang:1.14 as builder

WORKDIR /usr/src/app
COPY ./ ./

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main r-ssh


FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /usr/app

COPY --from=builder /usr/src/app/main ./main

EXPOSE 22
EXPOSE 80
EXPOSE 443

CMD ["./main"]
