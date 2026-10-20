FROM golang:1.27.3-trixie AS build

ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go main_test.go ./
RUN go test ./... \
    && go build -trimpath -ldflags="-s -w" -o /imds-emulator .

FROM gcr.io/distroless/static-debian13:latest

COPY --from=build /imds-emulator /imds-emulator

ENTRYPOINT ["/imds-emulator"]
