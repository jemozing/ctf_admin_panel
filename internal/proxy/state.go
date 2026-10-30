package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func atomicJSON(directory, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 16<<20 {
		return errors.New("proxy state exceeds bounded file size")
	}
	f, err := os.CreateTemp(directory, ".proxy-state-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	target := filepath.Join(directory, name)
	if info, e := os.Lstat(target); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return errors.New("proxy state target must be a private regular file")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	if err = os.Rename(temporary, target); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16<<20 {
		return errors.New("proxy state must be a bounded private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return errors.New("proxy state replaced while opening")
	}
	d := json.NewDecoder(io.LimitReader(f, (16<<20)+1))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("proxy state must contain one object")
	}
	return nil
}
