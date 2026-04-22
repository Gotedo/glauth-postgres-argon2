package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/alexedwards/argon2id"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/uptrace/opentelemetry-go-extra/otelsql"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/glauth/ldap"
)

type PostgresBackend struct{}

type Argon2PostgresHandler struct {
	db          *sql.DB
	log         *zerolog.Logger
	tracer      trace.Tracer
	backend     *PostgresBackend
	backendCfg  config.Backend
	cfg         *config.Config
	ldohelper   *handler.LDAPOpsHelper
	MemGroups   []config.Group
	yubikeyAuth *yubigo.YubiAuth
}

// Bind authenticates a user via a password
func (h *Argon2PostgresHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	ctx, span := h.tracer.Start(context.Background(), "plugins.argon2_postgres.Bind")
	defer span.End()

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

	// h.debugDumpUsers(ctx)

	var dbHash string
	err := h.db.QueryRowContext(ctx, `
        SELECT passbcrypt 
        FROM users 
        WHERE name = $1 OR mail = $2`, username, username).Scan(&dbHash)

	if err != nil {
		if err == sql.ErrNoRows {
			h.log.Err(err).Msg(fmt.Sprintf("User %s not found in DB", username))
		}
		// Yield to the upstream helper
		return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
	}

	// Trim any hidden newlines injected during the test setup
	dbHash = strings.TrimSpace(dbHash)

	match, err := argon2id.ComparePasswordAndHash(bindSimplePw, dbHash)
	if err != nil || !match {
		if err != nil {
			h.log.Err(err).Msg("Argon2 comparison error")
		}

		if !match {
			h.log.Error().Msg(fmt.Sprintf("Password mismatch for user %s", username))
		}

		// Yield to the upstream helper
		return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
	}

	h.log.Info().Str("username", username).Msg("Successful bind for user")
	return ldap.LDAPResultSuccess, nil
}

func (h *Argon2PostgresHandler) intToBool(value int) bool {
	if value == 0 {
		return false
	}
	return true
}

func (h *Argon2PostgresHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (f bool, u config.User, err error) {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.FindUser")
	defer span.End()

	// h.debugDumpUsers(ctx)

	var criterion string
	if searchByUPN {
		criterion = "lower(u.mail)"
	} else {
		criterion = "lower(u.name)"
	}

	h.log.Debug().
		Str("username", userName).
		Bool("searchByUPN", searchByUPN).
		Str("criterion", criterion).
		Msg("Attempting FindUser lookup")

	user := config.User{}
	var otherGroups string
	var disabled int

	err = h.db.QueryRowContext(
		ctx,
		fmt.Sprintf(`
      SELECT u.name, u.uidnumber, u.primarygroup, u.passbcrypt, u.passsha256, u.otpsecret, u.yubikey, u.disabled, u.othergroups, u.mail, u.givenname, u.sn
      FROM users u WHERE %s=lower(%s)`,
			criterion,
			h.backend.GetPrepareSymbol(),
		), userName).Scan(&user.Name, &user.UIDNumber, &user.PrimaryGroup, &user.PassBcrypt, &user.PassSHA256,
		&user.OTPSecret, &user.Yubikey, &disabled, &otherGroups, &user.Mail, &user.GivenName,
		&user.SN)

	if err != nil {
		if err == sql.ErrNoRows {
			h.log.Debug().Str("username", userName).Msg("User not found in database (clean miss)")
			return false, user, nil
		}
		h.log.Error().Err(err).Str("username", userName).Msg("Database error during FindUser")
		return false, user, err
	}

	user.Disabled = h.intToBool(disabled)
	user.UnixID = user.UIDNumber

	if user.Disabled {
		h.log.Warn().Str("username", userName).Msg("User is found but marked as disabled")
		return false, user, nil
	}

	h.log.Debug().Str("username", user.Name).Int("uid", user.UIDNumber).Msg("User successfully located and scanned")

	if otherGroups != "" {
		for _, g := range strings.Split(otherGroups, ",") {
			gid, _ := strconv.Atoi(strings.TrimSpace(g))
			user.OtherGroups = append(user.OtherGroups, gid)
		}
	}

	if !h.cfg.Behaviors.IgnoreCapabilities {
		rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
        SELECT c.action,c.object
        FROM capabilities c WHERE userid=%s`,
			h.backend.GetPrepareSymbol()), user.UIDNumber)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				capability := config.Capability{}
				if err := rows.Scan(&capability.Action, &capability.Object); err == nil {
					user.Capabilities = append(user.Capabilities, capability)
				}
			}
		}
	}

	return true, user, nil
}

// LDAPOpsHandler Implementations
func (h *Argon2PostgresHandler) GetBackend() config.Backend {
	return h.backendCfg
}

func (h *Argon2PostgresHandler) GetLog() *zerolog.Logger {
	return h.log
}

func (h *Argon2PostgresHandler) GetCfg() *config.Config {
	return h.cfg
}

func (h *Argon2PostgresHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return h.yubikeyAuth
}

func (h *Argon2PostgresHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	ctx, span := h.tracer.Start(context.Background(), "plugins.argon2_postgres.Search")
	defer span.End()

	return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
}

func (h *Argon2PostgresHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "plugins.argon2_postgres.Add")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *Argon2PostgresHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "plugins.argon2_postgres.Modify")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *Argon2PostgresHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "plugins.argon2_postgres.Delete")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *Argon2PostgresHandler) Close(boundDn string, conn net.Conn) error {
	_, span := h.tracer.Start(context.Background(), "plugins.argon2_postgres.Close")
	defer span.End()

	stats.Frontend.Add("closes", 1)
	return nil
}

func (h *Argon2PostgresHandler) FindGroup(ctx context.Context, groupName string) (f bool, g config.Group, err error) {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.FindGroup")
	defer span.End()

	group := config.Group{}
	found := false

	err = h.db.QueryRowContext(
		ctx,
		fmt.Sprintf(`
			SELECT g.gidnumber FROM ldapgroups g WHERE lower(name)=%s`, h.backend.GetPrepareSymbol()), groupName).Scan(
		&group.GIDNumber)
	if err == nil {
		found = true
	}

	return found, group, err
}

func (h *Argon2PostgresHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.FindPosixAccounts")
	defer span.End()

	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups(ctx)
	if err != nil {
		return entries, err
	}

	rows, err := h.db.QueryContext(
		ctx,
		`
		SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr  
		FROM users u`)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	var otherGroups string
	var disabled int
	var sshKeys string
	var custattrstr string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups, &u.GivenName, &u.SN, &u.Mail, &u.LoginShell, &u.Homedir, &disabled, &sshKeys, &custattrstr)
		if err != nil {
			return entries, err
		}
		u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)
		u.Disabled = h.intToBool(disabled)
		u.SSHKeys = h.commaListToStringTable(ctx, sshKeys)

		entry := h.getAccount(ctx, hierarchy, u)

		if custattrstr != "{}" {
			var r map[string]interface{}
			err := json.Unmarshal([]byte(custattrstr), &r)
			if err != nil {
				return entries, err
			}
			for key, attr := range r {
				switch typedattr := attr.(type) {
				case []interface{}:
					var values []string
					for _, v := range typedattr {
						switch typedvalue := v.(type) {
						case string:
							values = append(values, handler.MaybeDecode(typedvalue))
						default:
							values = append(values, handler.MaybeDecode(fmt.Sprintf("%v", typedvalue)))
						}
					}
					entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: key, Values: values})
				default:
					h.log.Warn().Str("key", key).Interface("value", attr).Msg("Unable to map custom attribute")
				}
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func (h *Argon2PostgresHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.FindPosixGroups")
	defer span.End()

	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups(ctx)
	if err != nil {
		return entries, err
	}

	for _, g := range h.MemGroups {
		info := h.getGroup(ctx, hierarchy, g)
		if hierarchy != "groups" {
			info.DN = strings.Replace(info.DN, ",ou=groups,", fmt.Sprintf(",%s,", hierarchy), 1)
		}
		entries = append(entries, info)
	}

	return entries, nil
}

// Toolbox methods
func (h *Argon2PostgresHandler) commaListToIntTable(ctx context.Context, commaList string) []int {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.commaListToIntTable")
	defer span.End()

	if len(commaList) == 0 {
		return make([]int, 0)
	}
	rowsAsStrings := strings.Split(commaList, ",")
	rowsAsInts := make([]int, len(rowsAsStrings))
	for i, v := range rowsAsStrings {
		iv, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return rowsAsInts
		}
		rowsAsInts[i] = iv
	}
	return rowsAsInts
}

func (h *Argon2PostgresHandler) commaListToStringTable(ctx context.Context, commaList string) []string {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.commaListToStringTable")
	defer span.End()

	if len(commaList) == 0 {
		return make([]string, 0)
	}
	return strings.Split(commaList, ",")
}

func (h *Argon2PostgresHandler) memoizeGroups(ctx context.Context) ([]config.Group, error) {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.memoizeGroups")
	defer span.End()

	workMemGroups := make([]*config.Group, 0)
	rows, err := h.db.QueryContext(
		ctx,
		`
		SELECT g1.name,g1.gidnumber,ig.includegroupid 
		FROM ldapgroups g1 
		LEFT JOIN includegroups ig ON g1.gidnumber=ig.parentgroupid 
		LEFT JOIN ldapgroups g2 ON ig.includegroupid=g2.gidnumber`)
	if err != nil {
		return nil, errors.New("Unable to memoize groups list")
	}
	defer rows.Close()

	var groupName string
	var groupId int
	var includeId sql.NullInt64
	var pg *config.Group
	recentId := -1
	for rows.Next() {
		err := rows.Scan(&groupName, &groupId, &includeId)
		if err != nil {
			return nil, errors.New("Unable to memoize groups list")
		}
		if recentId != groupId {
			recentId = groupId
			g := config.Group{Name: groupName, GIDNumber: groupId}
			pg = &g
			workMemGroups = append(workMemGroups, &g)
		}
		if includeId.Valid {
			pg.IncludeGroups = append(pg.IncludeGroups, int(includeId.Int64))
		}
	}
	memGroups := make([]config.Group, len(workMemGroups))
	for i, v := range workMemGroups {
		memGroups[i] = config.Group{Name: v.Name, GIDNumber: v.GIDNumber, IncludeGroups: v.IncludeGroups}
	}
	return memGroups, nil
}

func (h *Argon2PostgresHandler) getGroupMemberDNs(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.getGroupMemberDNs")
	defer span.End()

	var insertOuUsers string
	if h.cfg.Behaviors.LegacyVersion > 0 && h.cfg.Behaviors.LegacyVersion <= 20100 {
		insertOuUsers = ""
	} else {
		insertOuUsers = ",ou=users"
	}
	members := make(map[string]bool)

	rows, err := h.db.QueryContext(
		ctx,
		`
			SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
			FROM users u`)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	var otherGroups string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}
		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backendCfg.NameFormatAsArray[0], u.Name, h.backendCfg.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), insertOuUsers, h.backendCfg.BaseDN)
			members[dn] = true
		} else {
			u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backendCfg.NameFormatAsArray[0], u.Name, h.backendCfg.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), insertOuUsers, h.backendCfg.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	for _, g := range h.MemGroups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid != gid {
					includegroupmembers := h.getGroupMemberDNs(ctx, includegroupid)

					for _, includegroupmember := range includegroupmembers {
						members[includegroupmember] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

func (h *Argon2PostgresHandler) getGroupMemberIDs(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.getGroupMemberIDs")
	defer span.End()

	members := make(map[string]bool)
	rows, err := h.db.QueryContext(
		ctx,
		`
			SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
			FROM users u`)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	var otherGroups string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}
		if u.PrimaryGroup == gid {
			members[u.Name] = true
		} else {
			u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					members[u.Name] = true
				}
			}
		}
	}

	for _, g := range h.MemGroups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					h.log.Warn().Msg(fmt.Sprintf("Group: %d - Ignoring myself as included group", includegroupid))
				} else {
					includegroupmemberids := h.getGroupMemberIDs(ctx, includegroupid)

					for _, includegroupmemberid := range includegroupmemberids {
						members[includegroupmemberid] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

func (h *Argon2PostgresHandler) getGroupDNs(ctx context.Context, gids []int) []string {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.getGroupDNs")
	defer span.End()

	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.MemGroups {
			if g.GIDNumber == gid {
				dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backendCfg.GroupFormatAsArray[0], g.Name, h.backendCfg.BaseDN)
				groups[dn] = true
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.GIDNumber != gid {
					includegroupdns := h.getGroupDNs(ctx, []int{g.GIDNumber})

					for _, includegroupdn := range includegroupdns {
						groups[includegroupdn] = true
					}
				}
			}
		}
	}

	g := []string{}
	for k := range groups {
		g = append(g, k)
	}

	sort.Strings(g)

	return g
}

func (h *Argon2PostgresHandler) getGroupName(ctx context.Context, gid int) string {
	_, span := h.tracer.Start(ctx, "plugins.argon2_postgres.getGroupName")
	defer span.End()

	for _, g := range h.MemGroups {
		if g.GIDNumber == gid {
			return g.Name
		}
	}
	return ""
}

func (h *Argon2PostgresHandler) getGroup(ctx context.Context, hierarchy string, g config.Group) *ldap.Entry {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.getGroup")
	defer span.End()

	asGroupOfUniqueNames := hierarchy == "ou=groups"

	attrs := []*ldap.EntryAttribute{}
	for _, groupAttr := range h.backendCfg.GroupFormatAsArray {
		attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{g.Name}})
	}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s via LDAP", g.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.GIDNumber)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: h.getGroupMemberDNs(ctx, g.GIDNumber)})
	if asGroupOfUniqueNames {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: h.getGroupMemberIDs(ctx, g.GIDNumber)})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
	}
	dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backendCfg.GroupFormatAsArray[0], g.Name, h.backendCfg.BaseDN)
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

func (h *Argon2PostgresHandler) getAccount(ctx context.Context, hierarchy string, u config.User) *ldap.Entry {
	ctx, span := h.tracer.Start(ctx, "plugins.argon2_postgres.getAccount")
	defer span.End()

	attrs := []*ldap.EntryAttribute{}
	for _, nameAttr := range h.backendCfg.NameFormatAsArray {
		attrs = append(attrs, &ldap.EntryAttribute{Name: nameAttr, Values: []string{u.Name}})
	}

	if len(u.GivenName) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.GivenName}})
	}

	if len(u.SN) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.SN}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{h.getGroupName(ctx, u.PrimaryGroup)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", u.UIDNumber)}})

	if u.Disabled {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"inactive"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
	}

	if len(u.Mail) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Mail}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "userPrincipalName", Values: []string{u.Mail}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount"}})

	if len(u.LoginShell) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{u.LoginShell}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})
	}

	if len(u.Homedir) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{u.Homedir}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + u.Name}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s via LDAP", u.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{fmt.Sprintf("%s via LDAP", u.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: h.getGroupDNs(ctx, append(u.OtherGroups, u.PrimaryGroup))})
	if len(u.SSHKeys) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "sshPublicKey", Values: u.SSHKeys})
	}
	var dn string
	if hierarchy == "" {
		dn = fmt.Sprintf("%s=%s,%s=%s,%s", h.backendCfg.NameFormatAsArray[0], u.Name, h.backendCfg.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), h.backendCfg.BaseDN)
	} else {
		dn = fmt.Sprintf("%s=%s,%s=%s,%s,%s", h.backendCfg.NameFormatAsArray[0], u.Name, h.backendCfg.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), hierarchy, h.backendCfg.BaseDN)
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

// NewPostgresHandler is the entry point glauth calls (as configured in your .cfg file)
func NewPostgresHandler(opts ...handler.Option) handler.Handler {
	backend := PostgresBackend{}

	configOpts := handler.Options{}
	for _, opt := range opts {
		opt(&configOpts)
	}

	db, err := otelsql.Open(
		backend.GetDriverName(),
		configOpts.Backend.Database,
		otelsql.WithAttributes(otlpDriverAttribute(backend)),
		otelsql.WithDBName(configOpts.Backend.Database),
	)
	if err != nil {
		configOpts.Logger.Error().Err(err).Msg(fmt.Sprintf("[argon2-postgres] unable to open SQL database named '%s'", configOpts.Backend.Database))
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		configOpts.Logger.Error().Err(err).Msg(fmt.Sprintf("[argon2-postgres] unable to communicate with SQL database error: %s", configOpts.Backend.Database))
		os.Exit(1)
	}

	// Schema setup & migration
	backend.CreateSchema(db)
	backend.MigrateSchema(db, func(db *sql.DB, tableName string, columnName string) bool {
		var found string
		err := db.QueryRowContext(context.Background(), fmt.Sprintf(`SELECT COUNT(%s) FROM %s`, columnName, tableName)).Scan(&found)
		return err == nil
	})

	configOpts.Logger.Info().Msg("[argon2-postgres] Database (" + backend.GetDriverName() + "::" + configOpts.Backend.Database + ") Plugin: Ready")

	ldohelper := handler.NewLDAPOpsHelper(configOpts.Tracer)

	return &Argon2PostgresHandler{
		db:          db,
		log:         configOpts.Logger,
		backend:     &backend,
		backendCfg:  configOpts.Backend,
		ldohelper:   &ldohelper,
		cfg:         configOpts.Config,
		tracer:      configOpts.Tracer,
		yubikeyAuth: configOpts.YubiAuth,
	}
}

// Helper to inspect the table state during tests
// func (h *Argon2PostgresHandler) debugDumpUsers(ctx context.Context) {
// 	rows, err := h.db.QueryContext(ctx, "SELECT name, mail, passbcrypt FROM users")
// 	if err != nil {
// 		h.log.Debug().Err(err).Msg("DEBUG DUMP: Failed to query users table")
// 		return
// 	}
// 	defer rows.Close()

// 	h.log.Debug().Msg("--- DEBUG DUMP: Current Users in DB ---")
// 	for rows.Next() {
// 		var name, mail, hash string
// 		if err := rows.Scan(&name, &mail, &hash); err == nil {
// 			h.log.Debug().Msg(fmt.Sprintf("User: %s | Mail: %s | Hash: %.15s...", name, mail, hash))
// 		}
// 	}
// 	h.log.Debug().Msg("--- END DEBUG DUMP ---")
// }

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

func otlpDriverAttribute(backend PostgresBackend) attribute.KeyValue {
	switch backend.GetDriverName() {
	case "sqlite3":
		return semconv.DBSystemSqlite
	case "postgres":
		return semconv.DBSystemPostgreSQL
	case "mysql":
		return semconv.DBSystemMySQL
	default:
		return semconv.DBSystemOtherSQL
	}
}
