FROM golang:1.19

WORKDIR /kraken

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY Makefile ./
COPY assets assets
COPY cmd cmd
COPY util util

RUN make

WORKDIR /kraken/cmd/server

CMD [ "./server" ]
