# syntax=docker/dockerfile:1

# ---- Bauen (läuft auf der Architektur des Build-Rechners, kompiliert für die Zielarchitektur) ----
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/certbumblebee . \
 && mkdir -p /out/data /out/certs

# ---- Laufzeit: nur das Programm, die Stammzertifikate und zwei Ordner ----
FROM scratch
LABEL org.opencontainers.image.title="Certbumblebee" \
      org.opencontainers.image.description="TLS-Zertifikate holen, ablegen und automatisch erneuern (Let's Encrypt, Cloudflare-DNS, selbstsigniert)" \
      org.opencontainers.image.authors="Dzhan Chelebi" \
      org.opencontainers.image.source="https://github.com/ddzhan19/certbumblebee" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/certbumblebee /certbumblebee
# Die Ordner gehören dem Benutzer 10001, damit auch frische Volumes beschreibbar sind.
COPY --from=build --chown=10001:10001 /out/data /data
COPY --from=build --chown=10001:10001 /out/certs /certs

ENV ZA_CONTAINER=1 \
    ZA_DATA=/data \
    ZA_LISTEN=:8080

USER 10001:10001
VOLUME ["/data", "/certs"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=6s --start-period=20s --retries=3 \
    CMD ["/certbumblebee", "healthcheck"]

# SIGTERM beendet den Dauerbetrieb geordnet (laufende Vorgänge werden abgebrochen, Einträge bei Cloudflare aufgeräumt).
ENTRYPOINT ["/certbumblebee"]
CMD ["serve"]
