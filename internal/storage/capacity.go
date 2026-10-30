package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// Capacity obtains free space for the opened directory's filesystem rather
// than a subsequently resolved pathname. It never creates missing directories.
func Capacity(directory string) (Space, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Space{}, fmt.Errorf("absolute clean capacity path required")
	}
	before, err := os.Lstat(directory)
	if err != nil {
		return Space{}, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return Space{}, fmt.Errorf("capacity path must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Space{}, err
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		return Space{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return Space{}, fmt.Errorf("capacity path replaced during open")
	}
	return capacity(file)
}
