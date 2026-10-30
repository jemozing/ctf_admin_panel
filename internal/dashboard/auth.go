package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleDefender Role = "defender"
	RoleViewer   Role = "viewer"
)

type User struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Role            Role      `json:"role"`
	Disabled        bool      `json:"disabled"`
	SensitiveAccess bool      `json:"sensitive_access"`
	CreatedAt       time.Time `json:"created_at"`
}

type session struct {
	User       User
	Hash, CSRF string
	Expires    time.Time
}

type AuditEvent struct {
	ID          int64  `json:"id"`
	At          string `json:"at"`
	Actor       string `json:"actor"`
	Action      string `json:"action"`
	Target      string `json:"target"`
	Result      string `json:"result"`
	OperationID string `json:"operation_id,omitempty"`
}

const authSchema = `
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','defender','viewer')), disabled INTEGER NOT NULL DEFAULT 0,
 sensitive_access INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, operation_id TEXT NOT NULL DEFAULT ''
);
`

func openAuth(directory string) (*sql.DB, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, fmt.Errorf("dashboard state directory must be canonical and absolute")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("dashboard state directory must be private and cannot be a symlink")
	}
	filename := filepath.Join(directory, "dashboard.sqlite")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err = f.Close(); err != nil {
			return nil, err
		}
	} else if !os.IsExist(err) {
		return nil, err
	}
	info, err = os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("dashboard database must be a private regular file")
	}
	u := url.URL{Scheme: "file", Path: filename}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*sql.DB, error) { db.Close(); return nil, err }
	if _, err = db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fail(err)
	}
	if _, err = db.Exec(authSchema); err != nil {
		return fail(err)
	}
	if _, err = db.Exec("DELETE FROM sessions WHERE expires_at<=?", time.Now().Unix()); err != nil {
		return fail(err)
	}
	return db, nil
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,63}$`)

func validateUser(username, password string, role Role) error {
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("username must contain 3..64 lowercase ASCII letters, digits, dot, underscore or hyphen")
	}
	if len(password) < 12 || len(password) > 1024 {
		return fmt.Errorf("password must contain 12..1024 bytes")
	}
	if role != RoleAdmin && role != RoleDefender && role != RoleViewer {
		return fmt.Errorf("invalid role")
	}
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func userID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "u-" + hex.EncodeToString(b), nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return "$argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=1" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// CreateAdmin bootstraps the first account locally. It never changes existing users.
func (s *Server) CreateAdmin(ctx context.Context, username, password string) error {
	if err := validateUser(username, password, RoleAdmin); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	id, err := userID()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("bootstrap is available only when there are no users")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO users(id,username,password_hash,role,sensitive_access,created_at) VALUES(?,?,?,?,?,?)", id, username, hash, RoleAdmin, true, time.Now().Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,target,result) VALUES(?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), "local-admin", "bootstrap", username, "succeeded"); err != nil {
		return err
	}
	return tx.Commit()
}

func scanUser(scanner interface{ Scan(...any) error }) (User, error) {
	var u User
	var created int64
	err := scanner.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.SensitiveAccess, &created)
	u.CreatedAt = time.Unix(created, 0).UTC()
	return u, err
}

const userColumns = "id,username,role,disabled,sensitive_access,created_at"

func (s *Server) getSession(ctx context.Context, token string) (session, error) {
	if len(token) != 43 {
		return session{}, sql.ErrNoRows
	}
	var out session
	var expires int64
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.disabled,u.sensitive_access,u.created_at,s.csrf,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, tokenHash(token)).Scan(&out.User.ID, &out.User.Username, &out.User.Role, &out.User.Disabled, &out.User.SensitiveAccess, &created, &out.CSRF, &expires)
	if err != nil {
		return session{}, err
	}
	if out.User.Disabled || time.Now().Unix() >= expires {
		return session{}, sql.ErrNoRows
	}
	out.User.CreatedAt = time.Unix(created, 0).UTC()
	out.Hash = tokenHash(token)
	out.Expires = time.Unix(expires, 0).UTC()
	return out, nil
}

func (s *Server) audit(ctx context.Context, actor, action, target, result, operationID string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit(at,actor,action,target,result,operation_id) VALUES(?,?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), actor, action, target, result, operationID)
	return err
}

func (s *Server) listUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userColumns+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func dbNotFound(err error) bool { return err == sql.ErrNoRows }
