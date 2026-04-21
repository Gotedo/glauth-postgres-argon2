package main

import (
	"database/sql"
	"fmt"
	"net"
	"strings"

	"github.com/alexedwards/argon2id"
	_ "github.com/lib/pq"

	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/nmcclain/ldap"
)

type PostgresBackend struct{}

type Argon2PostgresHandler struct {
	handler.Handler // embed the standard DB handler (search, groups, etc.)
	db              *sql.DB
}

func (h *Argon2PostgresHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	// Extract username from DN (same logic you had)
	firstRDN := strings.SplitN(bindDN, ",", 2)[0]
	parts := strings.SplitN(firstRDN, "=", 2)

	username := bindDN
	if len(parts) == 2 {
		username = strings.TrimSpace(parts[1])
	} else {
		username = strings.TrimSpace(username)
	}

	if username == "" {
		return ldap.LDAPResultInvalidCredentials, fmt.Errorf("invalid DN format")
	}

	var dbHash string
	err := h.db.QueryRow(`
        SELECT passbcrypt 
        FROM users 
        WHERE name = $1 OR mail = $1`, username, username).Scan(&dbHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return ldap.LDAPResultInvalidCredentials, fmt.Errorf("invalid credentials")
		}
		return ldap.LDAPResultOperationsError, err
	}

	match, err := argon2id.ComparePasswordAndHash(bindSimplePw, dbHash)
	if err != nil || !match {
		return ldap.LDAPResultInvalidCredentials, fmt.Errorf("invalid credentials")
	}

	return ldap.LDAPResultSuccess, nil
}

// NewPostgresHandler is the entry point glauth calls (as configured in your .cfg file)
func NewPostgresHandler(opts ...handler.Option) handler.Handler {
	backend := PostgresBackend{}

	// This gives us the full standard database handler (search, schema, groups, etc.)
	stdHandler := NewDatabaseHandler(backend, opts...)

	// We also open our own DB connection so the custom Bind can use Argon2
	configOpts := handler.Options{}
	for _, opt := range opts {
		opt(&configOpts)
	}

	db, err := sql.Open(backend.GetDriverName(), configOpts.Backend.Database)
	if err != nil {
		panic(fmt.Sprintf("Failed to open postgres connection for Argon2 handler: %v", err))
	}

	return &Argon2PostgresHandler{
		Handler: stdHandler,
		db:      db,
	}
}

func (b PostgresBackend) GetDriverName() string {
	return "postgres"
}

func (b PostgresBackend) GetPrepareSymbol() string {
	return "$1"
}

// Create db/schema if necessary
func (b PostgresBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	uidnumber INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups TEXT DEFAULT '',
	givenname TEXT DEFAULT '',
	sn TEXT DEFAULT '',
	mail TEXT DEFAULT '',
	loginshell TEXT DEFAULT '',
	homedirectory TEXT DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 TEXT DEFAULT '',
	passbcrypt TEXT DEFAULT '',
	otpsecret TEXT DEFAULT '',
	yubikey TEXT DEFAULT '',
	sshkeys TEXT DEFAULT '',
	custattr TEXT DEFAULT '{}')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_name on users(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS ldapgroups (id SERIAL PRIMARY KEY, name TEXT NOT NULL, gidnumber INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name on ldapgroups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id SERIAL PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS capabilities (id SERIAL PRIMARY KEY, userid INTEGER NOT NULL, action TEXT NOT NULL, object TEXT NOT NULL)")
	statement.Exec()
}

// Migrate schema if necessary
func (b PostgresBackend) MigrateSchema(db *sql.DB, checker func(*sql.DB, string, string) bool) {
	if !checker(db, "users", "sshkeys") {
		statement, _ := db.Prepare("ALTER TABLE users ADD COLUMN sshkeys TEXT DEFAULT ''")
		statement.Exec()
	}
	if checker(db, "groups", "name") {
		statement, _ := db.Prepare("DROP TABLE ldapgroups")
		statement.Exec()
		statement, _ = db.Prepare("ALTER TABLE groups RENAME TO ldapgroups")
		statement.Exec()
	}
}
