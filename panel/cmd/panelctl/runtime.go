package main

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/database"
)

var errUnsafeRuntimeRole = errors.New("runtime_role_has_unsafe_privileges")

// The runtime role can operate on current tables but cannot migrate, change
// schema checksums, or edit/delete audit. Only explicit owner CLI calls this.
func validRuntimeRole(role string) bool {
	return regexp.MustCompile(`^panel_runtime(?:_restore_[a-f0-9]{12})?$`).MatchString(role)
}

func provisionRuntime(ctx context.Context, pool *pgxpool.Pool, passwordFile string, names ...string) error {
	role := "panel_runtime"
	if len(names) > 1 {
		return errors.New("runtime_role_name_invalid")
	}
	if len(names) == 1 {
		role = names[0]
	}
	if !validRuntimeRole(role) {
		return errors.New("runtime_role_name_invalid")
	}
	b, e := appconfig.PrivateFile(passwordFile)
	if e != nil {
		return e
	}
	return provisionRuntimeTarget(ctx, pool, strings.TrimSpace(string(b)), role, "public")
}

// Names are fixed by the CLI; parameters keep integration fixtures isolated.
func provisionRuntimeTarget(ctx context.Context, pool *pgxpool.Pool, password, role, schema string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(password) {
		return errors.New("runtime_password_format_invalid")
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		return errors.New("runtime_provision_failed")
	}
	defer database.Rollback(tx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(72619871310402)"); e != nil {
		return errors.New("runtime_provision_failed")
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); e != nil {
		return errors.New("runtime_provision_failed")
	}
	action := "CREATE"
	if exists {
		if e = validateRuntimeRole(ctx, tx, role, schema); e != nil {
			return e
		}
		action = "ALTER"
	}
	quotedRole := pgx.Identifier{role}.Sanitize()
	// Password alphabet is restricted above. Parameter placeholders are not legal in CREATE ROLE.
	if _, e = tx.Exec(ctx, action+" ROLE "+quotedRole+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); e != nil {
		return errors.New("runtime_provision_failed")
	}
	var name string
	if e = tx.QueryRow(ctx, "SELECT current_database()").Scan(&name); e != nil {
		return errors.New("runtime_provision_failed")
	}
	if _, e = tx.Exec(ctx, "GRANT CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" TO "+quotedRole); e != nil {
		return errors.New("runtime_provision_failed")
	}
	if _, e = tx.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+quotedRole); e != nil {
		return errors.New("runtime_provision_failed")
	}
	for table, privileges := range runtimeTablePrivileges {
		if _, e = tx.Exec(ctx, "GRANT "+privileges+" ON "+pgx.Identifier{schema, table}.Sanitize()+" TO "+quotedRole); e != nil {
			return errors.New("runtime_provision_failed")
		}
	}
	// Fresh roles may inherit unsafe PUBLIC privileges too. Never commit a role
	// that can escape the same boundary we enforce for an existing role.
	if e = validateRuntimeRole(ctx, tx, role, schema); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return errors.New("runtime_provision_failed")
	}
	return nil
}

var runtimeTablePrivileges = map[string]string{
	"managed_connection_observations": "SELECT,INSERT,UPDATE",
	"server_nodes":                    "SELECT,INSERT,UPDATE",
	"managed_connections":             "SELECT,INSERT,UPDATE",
	"managed_connection_versions":     "SELECT,INSERT",
	"infrastructure_servers":          "SELECT,INSERT",
	"nodes_vpn_config_versions":       "SELECT,INSERT",
	"access_device_invites":           "SELECT,INSERT,UPDATE",
	"set_publications":                "SELECT,INSERT",
	"set_publication_targets":         "SELECT,INSERT,UPDATE",
	"subscription_sets":               "SELECT,INSERT,UPDATE",
	"subscription_set_versions":       "SELECT,INSERT",
	"account_set_assignments":         "SELECT,INSERT,UPDATE",
	"subscription_set_mutations":      "SELECT,INSERT",
	"bypass_accounts":                 "SELECT,INSERT,UPDATE",
	"bypass_leases":                   "SELECT,INSERT,UPDATE",
	"account_rooms":                   "SELECT,INSERT",
	"builder_drafts":                  "SELECT,INSERT,UPDATE",
	"builder_versions":                "SELECT,INSERT",
	"builder_mutations":               "SELECT,INSERT",
	"subscription_delivery":           "SELECT,INSERT,UPDATE",
	"subscriptions":                   "SELECT,INSERT,UPDATE",
	"subscription_releases":           "SELECT,INSERT",
	"subscription_release_status":     "SELECT,INSERT,UPDATE",
	"subscription_mutations":          "SELECT,INSERT",
	"catalog_sources":                 "SELECT,INSERT,UPDATE",
	"catalog_versions":                "SELECT,INSERT",
	"catalog_drafts":                  "SELECT,INSERT,UPDATE,DELETE",
	"catalog_mutations":               "SELECT,INSERT",
	"schema_migrations":               "SELECT",
	"audit_events":                    "SELECT,INSERT",
	"jobs":                            "SELECT,INSERT,UPDATE,DELETE",
	"system_check_results":            "SELECT,INSERT,UPDATE,DELETE",
	"identity_control":                "SELECT,INSERT,UPDATE,DELETE",
	"admins":                          "SELECT,INSERT,UPDATE,DELETE",
	"admin_sessions":                  "SELECT,INSERT,UPDATE,DELETE",
	"identity_rate_limits":            "SELECT,INSERT,UPDATE,DELETE",
	"access_groups":                   "SELECT",
	"access_users":                    "SELECT,INSERT,UPDATE",
	"access_entitlements":             "SELECT,INSERT,UPDATE",
	"access_devices":                  "SELECT,INSERT,UPDATE",
	"access_credentials":              "SELECT,INSERT,UPDATE",
	"access_blocks":                   "SELECT,INSERT,UPDATE",
	"access_challenges":               "SELECT,INSERT,UPDATE",
	"access_mutations":                "SELECT,INSERT",
	"access_outbox":                   "SELECT,INSERT",
	"access_key_state":                "SELECT,INSERT",
	"nodes_authority_state":           "SELECT,INSERT",
	"nodes_registry":                  "SELECT,INSERT,UPDATE",
	"nodes_enrollments":               "SELECT,INSERT,UPDATE",
	"nodes_admin_mutations":           "SELECT,INSERT",
	"nodes_heartbeat_boots":           "SELECT,INSERT,UPDATE",
	"nodes_signer_state":              "SELECT,INSERT",
	"nodes_commands":                  "SELECT,INSERT",
	"nodes_command_receipts":          "SELECT,INSERT",
	"nodes_control_state":             "SELECT,INSERT,UPDATE",
	"nodes_control_mutations":         "SELECT,INSERT",
	"nodes_certificate_renewals":      "SELECT,INSERT",
	"nodes_vpn_installations":         "SELECT,INSERT,UPDATE",
	"nodes_vpn_policies":              "SELECT,INSERT",
	"nodes_vpn_receipts":              "SELECT,INSERT",
	"nodes_vpn_observations":          "SELECT,INSERT,UPDATE",
}

// B1 supports a dedicated database and an unprivileged role, not adoption of a
// pre-existing general purpose identity. Reject drift instead of revoking grants
// or changing ownership that might belong to another installation.
func validateRuntimeRole(ctx context.Context, tx pgx.Tx, role, schema string) error {
	var unsafe bool
	err := tx.QueryRow(ctx, `SELECT
 r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
 OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid)
 OR EXISTS (SELECT 1 FROM pg_shdepend WHERE refclassid='pg_authid'::regclass AND refobjid=r.oid
   AND (deptype='o' OR (deptype='a' AND dbid NOT IN (0,(SELECT oid FROM pg_database WHERE datname=current_database())))))
 OR EXISTS (SELECT 1 FROM pg_db_role_setting WHERE setrole=r.oid)
 OR EXISTS (SELECT 1 FROM pg_database WHERE has_database_privilege(r.oid,oid,'CREATE'))
 OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname !~ '^pg_(temp|toast_temp)_'
   AND has_schema_privilege(r.oid,oid,'CREATE'))
 FROM pg_roles r WHERE r.rolname=$1`, role).Scan(&unsafe)
	if err != nil {
		return errors.New("runtime_privilege_check_failed")
	}
	if unsafe {
		return errUnsafeRuntimeRole
	}
	// Check effective table and column privileges, including PUBLIC ACLs and
	// grant options. Column-only UPDATE could otherwise bypass checksum/audit
	// checks even when has_table_privilege reports false.
	rows, err := tx.Query(ctx, `SELECT n.nspname,c.relname,p.privilege,
 has_table_privilege($1,c.oid,p.privilege),
 has_table_privilege($1,c.oid,p.privilege||' WITH GRANT OPTION'),
 CASE WHEN p.privilege IN ('SELECT','INSERT','UPDATE','REFERENCES')
   THEN has_any_column_privilege($1,c.oid,p.privilege) ELSE false END,
 CASE WHEN p.privilege IN ('SELECT','INSERT','UPDATE','REFERENCES')
   THEN has_any_column_privilege($1,c.oid,p.privilege||' WITH GRANT OPTION') ELSE false END
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege)
 WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema')
 AND n.nspname !~ '^pg_(toast|temp)'`, role)
	if err != nil {
		return errors.New("runtime_privilege_check_failed")
	}
	defer rows.Close()
	for rows.Next() {
		var namespace, table, privilege string
		var tableAccess, tableGrant, columnAccess, columnGrant bool
		if err = rows.Scan(&namespace, &table, &privilege, &tableAccess, &tableGrant, &columnAccess, &columnGrant); err != nil {
			return errors.New("runtime_privilege_check_failed")
		}
		allowed := namespace == schema && strings.Contains(","+runtimeTablePrivileges[table]+",", ","+privilege+",")
		if tableGrant || columnGrant || ((tableAccess || columnAccess) && !allowed) {
			return errUnsafeRuntimeRole
		}
	}
	if rows.Err() != nil {
		return errors.New("runtime_privilege_check_failed")
	}
	return nil
}
