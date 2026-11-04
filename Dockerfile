# Build context is the program home repository root.
FROM golang:1.23-bookworm AS build
ENV GOFLAGS=-p=2 GOTOOLCHAIN=local
WORKDIR /src
COPY WeftCodec-Go/go.mod WeftCodec-Go/go.sum ./WeftCodec-Go/
COPY WeftFS-Go/go.mod WeftFS-Go/go.sum ./WeftFS-Go/
WORKDIR /src/WeftFS-Go
RUN go mod download
COPY WeftCodec-Go /src/WeftCodec-Go
COPY WeftFS-Go /src/WeftFS-Go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/weftfs ./cmd/weftfs

FROM alpine:3.20
RUN apk add --no-cache ca-certificates fuse3
COPY --from=build /out/weftfs /usr/local/bin/weftfs
LABEL org.opencontainers.image.title="WeftFS-Go" \
      org.opencontainers.image.description="Independent Go WeftFS store and FUSE frontend" \
      org.opencontainers.image.source="https://github.com/infinityabundance/WeftFS-Go" \
      org.opencontainers.image.licenses="Apache-2.0"
# Mounting requires: --device /dev/fuse --cap-add SYS_ADMIN
ENTRYPOINT ["weftfs"]
