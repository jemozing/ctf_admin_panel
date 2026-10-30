package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxTLSProfiles = 128
const maxTLSPins = 1024

type certificateProfile struct {
	certificate tls.Certificate
	metadata    TLSCertificateMetadata
	chainDigest string
	validFrom   time.Time
	validUntil  time.Time
}

type tlsPinState struct {
	SchemaVersion int               `json:"schema_version"`
	Profiles      map[string]string `json:"profiles"`
}

func safeTLSOwner(info os.FileInfo, directory bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || info.Mode().Perm()&0027 != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode()&os.ModeSymlink == 0
	}
	return info.Mode().IsRegular() && st.Nlink == 1
}

func openTLSDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("private TLS directory must be canonical and absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("private TLS directory unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !safeTLSOwner(info, true) {
		_ = f.Close()
		return nil, errors.New("private TLS directory ownership or permissions invalid")
	}
	return f, nil
}

func readTLSFile(parent *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("private TLS material unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !safeTLSOwner(info, false) || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("private TLS material ownership, permissions or size invalid")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	actual, statErr := f.Stat()
	if err != nil || statErr != nil || len(data) > int(limit) || !os.SameFile(info, actual) || actual.Size() != info.Size() || !actual.ModTime().Equal(info.ModTime()) || !safeTLSOwner(actual, false) {
		return nil, errors.New("private TLS material changed while reading")
	}
	return data, nil
}

func (e *Engine) readCertificateProfile(id string) (*certificateProfile, error) {
	if !identifier.MatchString(id) {
		return nil, errors.New("invalid local certificate ID")
	}
	root, err := openTLSDirectory(e.options.TLSDirectory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fd, err := unix.Openat(int(root.Fd()), id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("local certificate profile unavailable")
	}
	dir := os.NewFile(uintptr(fd), id)
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !safeTLSOwner(info, true) {
		return nil, errors.New("local certificate profile ownership or permissions invalid")
	}
	certPEM, err := readTLSFile(dir, "certificate.pem", 128<<10)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readTLSFile(dir, "private-key.pem", 64<<10)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if err != nil || len(certificate.Certificate) < 1 || len(certificate.Certificate) > 16 {
		return nil, errors.New("local certificate pair or chain invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || len(leaf.DNSNames)+len(leaf.IPAddresses) < 1 || len(leaf.DNSNames)+len(leaf.IPAddresses) > 128 {
		return nil, errors.New("local certificate leaf or names invalid")
	}
	for _, name := range leaf.DNSNames {
		if len(name) > 253 {
			return nil, errors.New("local certificate name exceeds supported bounds")
		}
	}
	if len(leaf.ExtKeyUsage) > 0 {
		server := false
		for _, use := range leaf.ExtKeyUsage {
			server = server || use == x509.ExtKeyUsageServerAuth || use == x509.ExtKeyUsageAny
		}
		if !server {
			return nil, errors.New("local certificate does not permit server authentication")
		}
	}
	now := e.options.Now()
	chainHash := sha256.New()
	validFrom, validUntil := leaf.NotBefore, leaf.NotAfter
	var previous *x509.Certificate
	for _, der := range certificate.Certificate {
		part, parseErr := x509.ParseCertificate(der)
		if parseErr != nil || now.Before(part.NotBefore) || !now.Before(part.NotAfter) {
			return nil, errors.New("local certificate chain expired, premature or invalid")
		}
		if previous != nil && previous.CheckSignatureFrom(part) != nil {
			return nil, errors.New("local certificate chain order or signature invalid")
		}
		if part.NotBefore.After(validFrom) {
			validFrom = part.NotBefore
		}
		if part.NotAfter.Before(validUntil) {
			validUntil = part.NotAfter
		}
		_, _ = chainHash.Write(der)
		previous = part
	}
	certificate.Leaf = leaf
	fingerprint := sha256.Sum256(leaf.Raw)
	meta := TLSCertificateMetadata{ID: id, DNSNames: append([]string{}, leaf.DNSNames...), IPAddresses: []string{}, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, FingerprintSHA256: "sha256:" + hex.EncodeToString(fingerprint[:]), Valid: true}
	for _, ip := range leaf.IPAddresses {
		meta.IPAddresses = append(meta.IPAddresses, ip.String())
	}
	return &certificateProfile{certificate: certificate, metadata: meta, chainDigest: "sha256:" + hex.EncodeToString(chainHash.Sum(nil)), validFrom: validFrom, validUntil: validUntil}, nil
}

func routeTLSHostname(r Route) string {
	u, _ := url.Parse("https://" + r.Host)
	return strings.TrimSuffix(u.Hostname(), ".")
}

// Caller holds e.mu. Preflight never commits pins or other state.
func (e *Engine) prepareTLS(p Policy) (map[string]*certificateProfile, error) {
	profiles := map[string]*certificateProfile{}
	for _, r := range p.Routes {
		if !isTLSProfile(r.Protocol) {
			continue
		}
		id := r.TLS.CertificateID
		profile := profiles[id]
		if profile == nil {
			var err error
			profile, err = e.readCertificateProfile(id)
			if err != nil {
				return nil, err
			}
			if digest, ok := e.tlsPins.Profiles[id]; ok && digest != profile.chainDigest {
				return nil, errors.New("local certificate ID is immutable; install a new profile ID")
			}
			profiles[id] = profile
		}
		if profile.certificate.Leaf.VerifyHostname(routeTLSHostname(r)) != nil {
			return nil, errors.New("local certificate does not match exact route host")
		}
	}
	return profiles, nil
}

func (e *Engine) commitTLSPins(profiles map[string]*certificateProfile) error {
	next := tlsPinState{SchemaVersion: 1, Profiles: map[string]string{}}
	for id, digest := range e.tlsPins.Profiles {
		next.Profiles[id] = digest
	}
	changed := false
	for id, profile := range profiles {
		if next.Profiles[id] == "" {
			next.Profiles[id] = profile.chainDigest
			changed = true
		}
	}
	if len(next.Profiles) > maxTLSPins {
		return errors.New("immutable certificate history budget exhausted")
	}
	if changed {
		if atomicJSON(e.options.StateDirectory, "tls-profiles.json", next) != nil {
			return errors.New("immutable certificate history persistence failed")
		}
		e.tlsPins = next
	}
	return nil
}

func (e *Engine) routeTLSConfig(address string, hello *tls.ClientHelloInfo) (*tls.Config, error) {
	state := e.active.Load()
	route := state.routes[address]
	if route == nil || route.tlsProfile == nil || route.tlsConfig == nil {
		return nil, errors.New("TLS route unavailable")
	}
	if !tlsNameMatches(route.route, hello.ServerName) {
		return nil, errors.New("TLS server name does not match route")
	}
	now := e.options.Now()
	if now.Before(route.tlsProfile.validFrom) || !now.Before(route.tlsProfile.validUntil) {
		return nil, errors.New("TLS certificate is outside validity period")
	}
	return route.tlsConfig, nil
}

func tlsNameMatches(r Route, name string) bool {
	host := routeTLSHostname(r)
	sni := strings.TrimSuffix(name, ".")
	_, ipErr := netip.ParseAddr(host)
	return (sni != "" && strings.EqualFold(sni, host)) || (sni == "" && ipErr == nil)
}

func (e *Engine) TLSCertificates() (TLSCertificatePage, error) {
	page := TLSCertificatePage{Certificates: []TLSCertificateMetadata{}}
	root, err := openTLSDirectory(e.options.TLSDirectory)
	if err != nil {
		return page, err
	}
	defer root.Close()
	// A trusted directory may still contain many entries: keep listing bounded.
	entries, err := root.ReadDir(maxTLSProfiles + 1)
	if err != nil && err != io.EOF {
		return page, errors.New("local certificate inventory unavailable")
	}
	page.Total = len(entries)
	page.Truncated = len(entries) > maxTLSProfiles
	if page.Truncated {
		entries = entries[:maxTLSProfiles]
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, entry := range entries {
		if !identifier.MatchString(entry.Name()) {
			continue
		}
		profile, err := e.readCertificateProfile(entry.Name())
		if err != nil {
			page.Certificates = append(page.Certificates, TLSCertificateMetadata{ID: entry.Name(), DNSNames: []string{}, IPAddresses: []string{}, ErrorCode: "invalid_certificate_profile"})
			continue
		}
		if digest, ok := e.tlsPins.Profiles[entry.Name()]; ok && digest != profile.chainDigest {
			profile.metadata.Valid = false
			profile.metadata.ErrorCode = "immutable_profile_changed"
		}
		page.Certificates = append(page.Certificates, profile.metadata)
	}
	sort.Slice(page.Certificates, func(i, j int) bool { return page.Certificates[i].ID < page.Certificates[j].ID })
	return page, nil
}
