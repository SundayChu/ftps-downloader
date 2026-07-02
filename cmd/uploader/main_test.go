package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCombineUploadRemotePathPOSIX(t *testing.T) {
	got := combineUploadRemotePath("/remote/data", "RYM01")
	if got != "/remote/data/RYM01" {
		t.Fatalf("combine POSIX path = %q", got)
	}
}

func TestCombineUploadRemotePathGuardian(t *testing.T) {
	got := combineUploadRemotePath(`\CSTP96.$DATA.SKDATA91`, "RYM01")
	if got != `\CSTP96.$DATA.SKDATA91.RYM01` {
		t.Fatalf("combine Guardian path = %q", got)
	}
}

func TestLoadConfigSFTPOptions(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.properties")
	data := []byte("host=example.com\nuser=user\npass=pass\nuse_tls=false\nuse_sftp=true\nssh_key_path=C:\\keys\\id_rsa\nssh_host_key_check=true\n")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.UseSFTP {
		t.Fatal("expected use_sftp=true")
	}
	if cfg.UseTLS {
		t.Fatal("expected use_tls=false")
	}
	if cfg.SSHKeyPath != `C:\keys\id_rsa` {
		t.Fatalf("ssh_key_path = %q", cfg.SSHKeyPath)
	}
	if !cfg.SSHHostKeyCheck {
		t.Fatal("expected ssh_host_key_check=true")
	}
}
