package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseRemotePathGuardian(t *testing.T) {
	dir, file := parseRemotePath(`\CSTP96.$DATA.SKDATA91.RYM01`)
	if dir != `\CSTP96.$DATA.SKDATA91` || file != "RYM01" {
		t.Fatalf("parseRemotePath Guardian = (%q, %q)", dir, file)
	}

	dir, file = parseRemotePath(`$DATA.SKDATA91.RYM02`)
	if dir != `$DATA.SKDATA91` || file != "RYM02" {
		t.Fatalf("parseRemotePath Guardian without system = (%q, %q)", dir, file)
	}
}

func TestParseRemotePathPOSIX(t *testing.T) {
	dir, file := parseRemotePath("/remote/data/file.txt")
	if dir != "/remote/data" || file != "file.txt" {
		t.Fatalf("parseRemotePath POSIX = (%q, %q)", dir, file)
	}
}

func TestParseNonStopListLine(t *testing.T) {
	info, ok := parseNonStopListLine("RYM01 101 166440 25-Jun-2026 21:47:34", "RYM01")
	if !ok {
		t.Fatal("expected NonStop LIST line to parse")
	}
	if !info.sizeAvailable || info.size != 166440 {
		t.Fatalf("size = %d, available = %v", info.size, info.sizeAvailable)
	}
	wantTime := time.Date(2026, time.June, 25, 21, 47, 34, 0, time.Local)
	if !info.timeAvailable || !info.modTime.Equal(wantTime) {
		t.Fatalf("time = %v, available = %v", info.modTime, info.timeAvailable)
	}
}

func TestParseNonStopListLineFullPathName(t *testing.T) {
	info, ok := parseNonStopListLine(`\CSTP96.$DATA.SKDATA91.RYM02 101 2048 05-Jan-26 08:09`, "RYM02")
	if !ok {
		t.Fatal("expected full Guardian path LIST line to parse")
	}
	if !info.sizeAvailable || info.size != 2048 {
		t.Fatalf("size = %d, available = %v", info.size, info.sizeAvailable)
	}
	wantTime := time.Date(2026, time.January, 5, 8, 9, 0, 0, time.Local)
	if !info.timeAvailable || !info.modTime.Equal(wantTime) {
		t.Fatalf("time = %v, available = %v", info.modTime, info.timeAvailable)
	}
}

func TestFormatLogSize(t *testing.T) {
	if got := formatLogSize("166440"); got != "166440 bytes" {
		t.Fatalf("format numeric size = %q", got)
	}
	value := "無法取得 (上次記錄: 166440 bytes)"
	if got := formatLogSize(value); got != value {
		t.Fatalf("format textual size = %q", got)
	}
}

func TestShouldDownloadExistingFileFromInfoPrefersRemoteDateOverSize(t *testing.T) {
	recordedTime := time.Date(2026, time.June, 25, 21, 47, 34, 0, time.Local)
	remoteTime := recordedTime

	download, reason := shouldDownloadExistingFileFromInfo(100, recordedTime, -1, remoteTime, 200, true, true)
	if download {
		t.Fatalf("expected size difference to be ignored when remote date is not newer, reason=%q", reason)
	}
}

func TestShouldDownloadExistingFileFromInfoDownloadsWhenRemoteDateIsNewer(t *testing.T) {
	recordedTime := time.Date(2026, time.June, 25, 21, 47, 34, 0, time.Local)
	remoteTime := recordedTime.Add(time.Minute)

	download, reason := shouldDownloadExistingFileFromInfo(100, recordedTime, -1, remoteTime, 100, true, true)
	if !download {
		t.Fatalf("expected newer remote date to download, reason=%q", reason)
	}
}

func TestRemoteFileIsKnownEmpty(t *testing.T) {
	if !remoteFileIsKnownEmpty(0, true) {
		t.Fatal("expected known zero-size remote file to be empty")
	}
	if remoteFileIsKnownEmpty(0, false) {
		t.Fatal("expected unknown remote size not to be treated as empty")
	}
}

func TestConfiguredRemotePathsFromMappings(t *testing.T) {
	cfg := &Config{
		FileNames: []PathMapping{
			{RemotePath: " /remote/A "},
			{RemotePath: ""},
			{RemotePath: "/remote/A"},
			{RemotePath: "/remote/B"},
		},
	}

	got := configuredRemotePaths(cfg)
	want := []string{".", "/remote/A", "/remote/B"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configuredRemotePaths() = %v, want %v", got, want)
	}
}

func TestConfiguredRemotePathsFromRemoteDir(t *testing.T) {
	cfg := &Config{RemoteDir: " /remote/data "}
	got := configuredRemotePaths(cfg)
	want := []string{"/remote/data"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configuredRemotePaths() = %v, want %v", got, want)
	}
}

func TestShouldCreateInitialSnapshot(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{FileTimesDir: tmp}

	if !shouldCreateInitialSnapshot(cfg) {
		t.Fatal("expected initial snapshot to be needed before marker exists")
	}

	marker := initialSnapshotMarkerPath(cfg)
	if err := os.WriteFile(marker, []byte("done\n"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if shouldCreateInitialSnapshot(cfg) {
		t.Fatal("expected initial snapshot to be skipped after marker exists")
	}
}

func TestInitialSnapshotMarkerPathUsesLocalDirFallback(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{LocalDir: tmp}

	got := initialSnapshotMarkerPath(cfg)
	want := filepath.Join(tmp, ".initial_remote_listing_done")
	if got != want {
		t.Fatalf("initialSnapshotMarkerPath() = %q, want %q", got, want)
	}
}
