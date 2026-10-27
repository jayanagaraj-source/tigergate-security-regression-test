// Package archive holds tar extraction cases for GO-034.
package archive

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Untar writes every entry under dest without checking where it lands.
func Untar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err != nil {
			return err
		}
		target := filepath.Join(dest, header.Name) // GO-ZIP-TP-001
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}

// UntarContained skips entries that resolve outside dest.
func UntarContained(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err != nil {
			return err
		}
		target := filepath.Join(dest, header.Name) // GO-ZIP-TN-001
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}
