FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o /evidenced ./cmd/evidenced

FROM gcr.io/distroless/static:nonroot
COPY --from=build /evidenced /evidenced
USER 65532:65532
ENTRYPOINT ["/evidenced"]
