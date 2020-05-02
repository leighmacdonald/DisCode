FROM golang:1.14-buster
LABEL maintainer="Leigh MacDonald <leigh.macdonald@gmail.com>"
WORKDIR /discode
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build
EXPOSE 5555
CMD ["./discode"]