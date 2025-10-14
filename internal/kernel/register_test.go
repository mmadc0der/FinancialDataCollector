package kernel

import (
    "encoding/base64"
    "testing"
)

func TestSSHFingerprint(t *testing.T) {
    data := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMOCKEY example@host")
    fp1 := sshFingerprint(data)
    fp2 := sshFingerprint(data)
    if fp1 == "" || fp2 == "" || fp1 != fp2 {
        t.Fatalf("fingerprint not stable: %q vs %q", fp1, fp2)
    }
    // small change should produce different fingerprint
    fp3 := sshFingerprint(append(data, 'x'))
    if fp3 == fp1 { t.Fatalf("expected different fingerprint for different input") }
    // ensure Base64
    if _, err := base64.StdEncoding.DecodeString(fp1); err != nil {
        t.Fatalf("fingerprint is not base64: %v", err)
    }
}
