package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// removeFiles deletes the files in dir whose base name matches a pattern.
func removeFiles(dir string, patterns []string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, p := range patterns {
			if ok, _ := filepath.Match(p, d.Name()); ok {
				if err := os.Remove(path); err != nil {
					return err
				}
				n++
				break
			}
		}
		return nil
	})
	return n, err
}

// pack writes the directories and regular files under dir as a gzip tar,
// with paths relative to dir. It skips other file types, for example links.
func pack(dir string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uname, hdr.Gname, hdr.Uid, hdr.Gid = "", "", 0, 0
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	return errors.Join(err, tw.Close(), gz.Close())
}
