# Stage 1: Build the core binary and the plugin using GLAuth's module context
FROM golang:1.21 AS builder

# 1. Get the GLAuth source
WORKDIR /src
RUN git clone --branch v2.4.0 --depth 1 https://github.com/glauth/glauth.git

# Move into the module root
WORKDIR /src/glauth/v2

# 2. Update GLAuth's go.mod to include your Argon2 dependency
# We use 'go mod edit' to be precise and 'go mod tidy' to lock versions

# Force the module to look AT ITSELF for v2 imports (fixes the pkg/embed error)
RUN go mod edit -replace github.com/glauth/glauth/v2=./
RUN go mod edit -require github.com/alexedwards/argon2id@v1.0.0
RUN go mod edit -require github.com/lib/pq@v1.10.7
RUN go mod edit -require github.com/glauth/ldap@v0.0.0-20240419171521-1f14f5c1b4ad
RUN go mod download

# 3. Inject your custom code into the existing plugin path
# This makes your code part of the GLAuth module itself, inheriting its go.sum
COPY postgres.go ./pkg/plugins/glauth-postgres/postgres.go

# 4. Build the core binary
# We must use -buildvcs=false and avoid -trimpath to ensure identical hashes
RUN CGO_ENABLED=1 go build -buildvcs=false -o /app/glauth .

# 5. Build the plugin
# We build it FROM the GLAuth module context so it uses the SAME 'barcode' version
RUN CGO_ENABLED=1 go build -buildvcs=false -buildmode=plugin \
  -o /app/postgres.so \
  ./pkg/plugins/glauth-postgres/postgres.go

# Stage 2: Final Test Image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the perfectly matched core binary and plugin
COPY --from=builder /app/glauth /app/glauth
COPY --from=builder /app/postgres.so /app/postgres.so

# Ensure the config can find the plugin
RUN ln -s /app/postgres.so /app/postgres

CMD ["/app/glauth", "-c", "/app/config/glauth.cfg"]