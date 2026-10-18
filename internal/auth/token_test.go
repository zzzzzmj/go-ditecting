package auth

import "testing"

func TestTokenLifecycle(t *testing.T) {
	m := New("a-long-test-secret", "analyst", "password")
	token, err := m.Authenticate("analyst", "password")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.Verify(token)
	if err != nil || claims.Subject != "analyst" || claims.Role != "analyst" {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if _, err := m.Authenticate("analyst", "wrong"); err == nil {
		t.Fatal("expected rejected password")
	}
}
