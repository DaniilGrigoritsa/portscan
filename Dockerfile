FROM golang:1.25.5

ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1

WORKDIR /src
COPY . .

RUN go build ./... && go vet ./...

CMD ["go", "test", "-race", "-count=1", "./..."]
