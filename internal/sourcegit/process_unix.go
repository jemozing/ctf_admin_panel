//go:build linux || darwin

package sourcegit

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func prepareRepository(name string) error {
	if os.Geteuid() == 0 {
		return os.Chown(name, 65534, 65534)
	}
	return nil
}
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 65534, Gid: 65534}
	}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
}
