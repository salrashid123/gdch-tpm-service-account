# go1.25.1 linux/amd64
FROM docker.io/golang:1.26.2-bookworm as build

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN go build -o /go/bin/stsserver server.go 
RUN chown root:root /go/bin/stsserver

# base-debian11-root
FROM gcr.io/distroless/base@sha256:74ddbf52d93fafbdd21b399271b0b4aac1babf8fa98cab59e5692e01169a1348
COPY --from=build /go/src/app/certs/root-ca.crt /certs/root-ca.crt
COPY --from=build /go/src/app/certs/sts.crt /certs/sts.crt
COPY --from=build /go/src/app/certs/sts.key /certs/sts.key
COPY --from=build /go/src/app/certs/public_key.pem /certs/public_key.pem
COPY --from=build /go/bin/stsserver /stsserver

EXPOSE 8080
ENTRYPOINT [ "/stsserver", "-httpport=:8080", "--skipTLS", "--debug" ]
