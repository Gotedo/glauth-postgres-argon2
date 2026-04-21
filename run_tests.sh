#!/usr/bin/env bash
set -euo pipefail

# ====================== 1. Dependency Checks ======================
for cmd in docker docker-compose ldapsearch node npm make; do
  case $cmd in
    docker)           msg="docker" ;;
    docker-compose)   msg="docker-compose or docker compose" ;;
    ldapsearch)       msg="ldap-utils (Debian/Ubuntu) or openldap (macOS)" ;;
    node)             msg="nodejs" ;;
    npm)              msg="npm" ;;
    make)             msg="make" ;;
  esac
  if ! command -v "$cmd" &>/dev/null; then
    echo "❌ ERROR: $cmd is not installed. Please install $msg."
    exit 1
  fi
done

# ====================== 2. Setup Test Directory ======================
TEST_DIR="./tests"
echo "📁 Creating test environment in $TEST_DIR..."
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# ====================== 3. Generate real Argon2 hash (fixed async) ======================
echo "🔐 Generating Argon2id hash..."
cd "$TEST_DIR"
npm init -y >/dev/null 2>&1
npm install phc-argon2 >/dev/null 2>&1

TEST_PASSWORD="TestPassword123!"

# Reliable async capture
ARGON2_HASH=$(node -e '
  const argon2 = require("phc-argon2");
  (async () => {
    const hash = await argon2.hash("'"$TEST_PASSWORD"'");
    console.log(hash);
  })();
')

echo "✅ Hash generated: $ARGON2_HASH"
cd ..

# ====================== 4. Generate Test Files ======================
echo "🔧 Generating test configurations..."

# SQL Init Script (fixed table names + minimal schema)
cat <<EOF > "$TEST_DIR/init-test.sql"
CREATE SCHEMA IF NOT EXISTS glauth;

CREATE TABLE IF NOT EXISTS glauth.users (
    id SERIAL PRIMARY KEY,
    uidnumber INTEGER NOT NULL,
    name TEXT NOT NULL,
    mail TEXT,
    givenname TEXT,
    sn TEXT,
    disabled SMALLINT DEFAULT 0,
    passbcrypt TEXT,
    primarygroup INTEGER NOT NULL,
    othergroups TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS glauth.ldapgroups (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    gidnumber INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS glauth.includegroups (
    parentgroupid INTEGER NOT NULL,
    includegroupid INTEGER NOT NULL
);

-- Seed test data
INSERT INTO glauth.ldapgroups (id, name, gidnumber) VALUES (500, 'GlobalUsers', 500);

INSERT INTO glauth.users (id, uidnumber, name, mail, givenname, sn, passbcrypt, primarygroup)
VALUES (1, 1, 'testuser', 'testuser@gotedo.com', 'Test', 'User', '$ARGON2_HASH', 500);
EOF

# GLAuth Config (unchanged except plugin name is now correct via copy)
cat <<EOF > "$TEST_DIR/glauth-test.cfg"
debug = true

[api]
  enabled = true
  listen = "0.0.0.0:5555"

[ldap]
  enabled = true
  listen = "0.0.0.0:3893"
  tls = false

[ldaps]
  enabled = false
  listen = "0.0.0.0:3894"

[backend]
  datastore = "plugin"
  plugin = "/app/postgres.so"
  pluginhandler = "NewPostgresHandler"
  database = "postgres://testadmin:testpass@postgres:5432/glauth_test?sslmode=disable&search_path=glauth"
  baseDN = "dc=gotedo,dc=com"
EOF

# Docker Compose (now uses volume mount for the plugin)
cat <<EOF > "$TEST_DIR/docker-compose.test.yml"
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: testadmin
      POSTGRES_PASSWORD: testpass
      POSTGRES_DB: glauth_test
    volumes:
      - ./init-test.sql:/docker-entrypoint-initdb.d/init-test.sql:ro
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U testadmin"]
      interval: 2s
      timeout: 5s
      retries: 5

  glauth:
    build:
      context: ..
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "3893:3893"
    volumes:
      - ./glauth-test.cfg:/app/config/glauth.cfg:ro
EOF

# ====================== 5. Spin up the test environment ======================
echo "🚀 Starting test containers..."
docker-compose -f "$TEST_DIR/docker-compose.test.yml" up -d --build

echo "⏳ Waiting for services to be ready..."
sleep 8

# ====================== 6. Execute Functional Tests ======================
echo "----------------------------------------"
echo "🧪 RUNNING FUNCTIONAL TESTS"
echo "----------------------------------------"
TESTS_PASSED=0
TESTS_FAILED=0

# Test A: Valid Authentication
echo -n "Test A: Valid Authentication ... "
if ldapsearch -H ldap://localhost:3893 -D "cn=testuser,dc=gotedo,dc=com" -w "$TEST_PASSWORD" -b "dc=gotedo,dc=com" "(cn=testuser)" > /dev/null 2>&1; then
    echo "✅ PASSED"
    ((TESTS_PASSED++))
else
    echo "❌ FAILED"
    ((TESTS_FAILED++))
fi

# Test B: Invalid Authentication
echo -n "Test B: Invalid Authentication ... "
if ! ldapsearch -H ldap://localhost:3893 -D "cn=testuser,dc=gotedo,dc=com" -w "WrongPassword123!" -b "dc=gotedo,dc=com" "(cn=testuser)" > /dev/null 2>&1; then
    echo "✅ PASSED"
    ((TESTS_PASSED++))
else
    echo "❌ FAILED (It allowed an invalid password!)"
    ((TESTS_FAILED++))
fi

# Test C: Unknown User
echo -n "Test C: Unknown User ... "
if ! ldapsearch -H ldap://localhost:3893 -D "cn=ghostuser,dc=gotedo,dc=com" -w "$TEST_PASSWORD" -b "dc=gotedo,dc=com" "(cn=ghostuser)" > /dev/null 2>&1; then
    echo "✅ PASSED"
    ((TESTS_PASSED++))
else
    echo "❌ FAILED (It allowed a non-existent user!)"
    ((TESTS_FAILED++))
fi

echo "----------------------------------------"
echo "📊 RESULTS: $TESTS_PASSED Passed, $TESTS_FAILED Failed"
echo "----------------------------------------"

# ====================== 7. Teardown & Debug ======================
if [ "$TESTS_FAILED" -ne 0 ]; then
    echo "⚠️  Some tests failed. Dumping GLAuth logs for inspection:"
    echo "----------------------------------------"
    docker-compose -f "$TEST_DIR/docker-compose.test.yml" logs glauth
    echo "----------------------------------------"
    echo "🧹 Cleaning up test environment..."
    docker-compose -f "$TEST_DIR/docker-compose.test.yml" down -v --remove-orphans
    exit 1
else
    echo "🧹 Cleaning up test environment..."
    docker-compose -f "$TEST_DIR/docker-compose.test.yml" down -v --remove-orphans
    echo "🎉 All tests passed successfully!"
    exit 0
fi