package executor

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
)

// Independent CLI Manager instances do not share Go mutexes. Admission is a
// short cross-process gate around the durable guard and its submission/approval
// commit. The queued cutover journal then carries the exclusion after a crash.
func (m *Manager) lockCutoverAdmission() (func(), error) {
	lock, err := m.privateExecutorLock(".operation-admission")
	if err != nil {
		return nil, err
	}
	return func() { _ = lock.Close() }, nil
}

func (m *Manager) privateExecutorLock(name string) (*maintenance.Lock, error) {
	if !filepath.IsAbs(m.Config.StateDirectory) || filepath.Clean(m.Config.StateDirectory) != m.Config.StateDirectory || m.Config.StateDirectory == "/" {
		return nil, errors.New("executor control lock requires a canonical private state directory")
	}
	path := filepath.Join(m.Config.StateDirectory, name)
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	lock, err := maintenance.Acquire(path, true)
	if errors.Is(err, maintenance.ErrActive) {
		return nil, proxyInput("Another executor process is admitting an operation; retry after it completes")
	}
	return lock, err
}
