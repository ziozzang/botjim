package attrs

import "testing"

// TestSafeXattrName: only user.* xattrs from a received manifest may be
// applied — security.capability / ACL / trusted.* are privilege-bearing
// and must never be set from an untrusted sender.
func TestSafeXattrName(t *testing.T) {
	allow := []string{"user.mime_type", "user.anything", "user."}
	deny := []string{
		"security.capability", "security.selinux",
		"system.posix_acl_access", "system.posix_acl_default",
		"trusted.foo", "btrfs.something", "", "User.Caps", "os2.ea",
	}
	for _, n := range allow {
		if !safeXattrName(n) {
			t.Errorf("safe xattr %q rejected", n)
		}
	}
	for _, n := range deny {
		if safeXattrName(n) {
			t.Errorf("dangerous xattr %q allowed", n)
		}
	}
}
