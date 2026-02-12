package apiserver

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func createBloatedDB(t *testing.T, path string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE t(k TEXT, v BLOB)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if _, err := db.Exec("INSERT INTO t VALUES (?, randomblob(4096))", i); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("DELETE FROM t WHERE k != '0'"); err != nil {
		t.Fatal(err)
	}

	// Simulate litestream recovery artifacts (sqlite3 .recover output).
	if _, err := db.Exec("CREATE TABLE lost_and_found(rootpgno INT, pgno INT, nfield INT, id INT, c0, c1, c2, c3)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE lost_and_found_0(rootpgno INT, pgno INT, nfield INT, id INT, c0)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		if _, err := db.Exec("INSERT INTO lost_and_found VALUES (?, ?, 4, ?, randomblob(1024), randomblob(1024), randomblob(1024), randomblob(1024))", i, i, i); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO lost_and_found_0 VALUES (?, ?, 1, ?, randomblob(2048))", i, i, i); err != nil {
			t.Fatal(err)
		}
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestEnableAutoVacuum(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	before := createBloatedDB(t, dbPath)
	t.Logf("before: %d bytes", before)

	if err := enableAutoVacuum(dbPath); err != nil {
		t.Fatalf("enableAutoVacuum: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var mode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 2 {
		t.Errorf("auto_vacuum = %d, want 2", mode)
	}

	// Verify lost_and_found tables were dropped.
	var lostCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'lost_and_found%'").Scan(&lostCount); err != nil {
		t.Fatal(err)
	}
	if lostCount != 0 {
		t.Errorf("lost_and_found tables remain: %d", lostCount)
	}

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	after := fi.Size()
	t.Logf("after: %d bytes", after)

	if after >= before {
		t.Errorf("DB did not shrink: before=%d after=%d", before, after)
	}
}
