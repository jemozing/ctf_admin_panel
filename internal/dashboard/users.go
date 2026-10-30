package dashboard

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) users(w http.ResponseWriter, r *http.Request, current session) {
	if r.Method == http.MethodGet {
		users, err := s.listUsers(r.Context())
		if err != nil {
			internalError(w)
			return
		}
		writeJSON(w, 200, users)
		return
	}
	if !method(w, r, "POST") {
		return
	}
	var input struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		Role            Role   `json:"role"`
		SensitiveAccess bool   `json:"sensitive_access"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if err := validateUser(input.Username, input.Password, input.Role); err != nil {
		apiError(w, 400, "invalid_user", err.Error())
		return
	}
	if !s.acquirePasswordSlot(w) {
		return
	}
	defer func() { <-s.passwordSlots }()
	hash, err := hashPassword(input.Password)
	if err != nil {
		internalError(w)
		return
	}
	id, err := userID()
	if err != nil {
		internalError(w)
		return
	}
	if input.Role == RoleAdmin {
		input.SensitiveAccess = true
	}
	u := User{ID: id, Username: input.Username, Role: input.Role, SensitiveAccess: input.SensitiveAccess, CreatedAt: time.Now().UTC()}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users WHERE username=?", input.Username).Scan(&count); err != nil {
		internalError(w)
		return
	}
	if count != 0 {
		apiError(w, 409, "user_exists", "Username already exists")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO users(id,username,password_hash,role,sensitive_access,created_at) VALUES(?,?,?,?,?,?)", u.ID, u.Username, hash, u.Role, u.SensitiveAccess, u.CreatedAt.Unix()); err != nil {
		internalError(w)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit(at,actor,action,target,result) VALUES(?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), current.User.ID, "user.create", u.ID, "succeeded"); err != nil {
		internalError(w)
		return
	}
	if err = tx.Commit(); err != nil {
		internalError(w)
		return
	}
	writeJSON(w, 201, u)
}

func (s *Server) user(w http.ResponseWriter, r *http.Request, current session) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) > 2 || parts[0] == "" {
		apiError(w, 404, "not_found", "user endpoint not found")
		return
	}
	id := parts[0]
	if len(parts) == 2 {
		if parts[1] != "revoke-sessions" {
			apiError(w, 404, "not_found", "user endpoint not found")
			return
		}
		if !method(w, r, "POST") {
			return
		}
		tx, err := s.db.BeginTx(r.Context(), nil)
		if err != nil {
			internalError(w)
			return
		}
		defer tx.Rollback()
		var exists int
		if err = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users WHERE id=?", id).Scan(&exists); err != nil {
			internalError(w)
			return
		}
		if exists == 0 {
			apiError(w, 404, "not_found", "user not found")
			return
		}
		if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=?", id); err != nil {
			internalError(w)
			return
		}
		if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit(at,actor,action,target,result) VALUES(?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), current.User.ID, "session.revoke", id, "succeeded"); err != nil {
			internalError(w)
			return
		}
		if err = tx.Commit(); err != nil {
			internalError(w)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if !method(w, r, "PATCH") {
		return
	}
	var input struct {
		Role            *Role   `json:"role"`
		Disabled        *bool   `json:"disabled"`
		SensitiveAccess *bool   `json:"sensitive_access"`
		Password        *string `json:"password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if input.Role == nil && input.Disabled == nil && input.SensitiveAccess == nil && input.Password == nil {
		apiError(w, 400, "invalid_request", "At least one user property is required")
		return
	}
	if input.Role != nil && *input.Role != RoleAdmin && *input.Role != RoleDefender && *input.Role != RoleViewer {
		apiError(w, 400, "invalid_role", "Unknown role")
		return
	}
	passwordHash := ""
	if input.Password != nil {
		if len(*input.Password) < 12 || len(*input.Password) > 1024 {
			apiError(w, 400, "invalid_password", "Password must contain 12..1024 bytes")
			return
		}
		if !s.acquirePasswordSlot(w) {
			return
		}
		defer func() { <-s.passwordSlots }()
		var err error
		passwordHash, err = hashPassword(*input.Password)
		if err != nil {
			internalError(w)
			return
		}
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	u, err := scanUser(tx.QueryRowContext(r.Context(), "SELECT "+userColumns+" FROM users WHERE id=?", id))
	if dbNotFound(err) {
		apiError(w, 404, "not_found", "user not found")
		return
	}
	if err != nil {
		internalError(w)
		return
	}
	wasAdmin := u.Role == RoleAdmin && !u.Disabled
	if input.Role != nil {
		u.Role = *input.Role
	}
	if input.Disabled != nil {
		u.Disabled = *input.Disabled
	}
	if input.SensitiveAccess != nil {
		u.SensitiveAccess = *input.SensitiveAccess
	}
	if u.Role == RoleAdmin {
		u.SensitiveAccess = true
	}
	if wasAdmin && (u.Role != RoleAdmin || u.Disabled) {
		var other int
		if err = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND id!=?", id).Scan(&other); err != nil {
			internalError(w)
			return
		}
		if other == 0 {
			apiError(w, 409, "last_admin", "The last active administrator cannot be disabled or demoted")
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE users SET role=?,disabled=?,sensitive_access=? WHERE id=?", u.Role, u.Disabled, u.SensitiveAccess, id); err != nil {
		internalError(w)
		return
	}
	if passwordHash != "" {
		if _, err = tx.ExecContext(r.Context(), "UPDATE users SET password_hash=? WHERE id=?", passwordHash, id); err != nil {
			internalError(w)
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=?", id); err != nil {
		internalError(w)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit(at,actor,action,target,result) VALUES(?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), current.User.ID, "user.update", id, "succeeded"); err != nil {
		internalError(w)
		return
	}
	if err = tx.Commit(); err != nil {
		internalError(w)
		return
	}
	writeJSON(w, 200, u)
}

func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), "SELECT id,at,actor,action,target,result,operation_id FROM audit ORDER BY id DESC LIMIT 200")
	if err != nil {
		internalError(w)
		return
	}
	defer rows.Close()
	result := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err = rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Result, &e.OperationID); err != nil {
			internalError(w)
			return
		}
		result = append(result, e)
	}
	if rows.Err() != nil {
		internalError(w)
		return
	}
	writeJSON(w, 200, result)
}
