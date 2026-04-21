# Stage 1: Build the plugin
# Golang version matches the version in go.mod
FROM golang:1.26.2 AS builder

WORKDIR /build

# 1. Copy the entire local project tree
COPY . .

# 2. Download dependencies (uses your local go.mod/go.sum)
RUN go mod tidy && go mod download

# 3. Build the plugin using the Makefile
RUN make plugin

# Stage 4: Final Test Image
FROM glauth/glauth:v2.5.0

# Copy the securely compiled plugin from the builder stage.
# The wildcard (linux_*) ensures this works whether you build on an Intel or ARM machine.
# We rename it to postgres.so to match your existing glauth-test.cfg backend plugin path.
COPY --from=builder /build/bin/linux_*/argon2-postgres.so /app/postgres.so

CMD ["/app/glauth", "-c", "/app/config/glauth.cfg"]