package secretsengine

import (
	"sync"
	"testing"
)

func TestFindSecretsConnectionStrings(t *testing.T) {
	if err := LoadRules(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"postgres://demo:example@localhost/db",
		"postgresql://demo:example@localhost/db",
		"mongodb://demo:example@localhost/db",
		"mongodb+srv://demo:example@localhost/db",
	} {
		t.Run(secret, func(t *testing.T) {
			if got := FindSecrets("exporter --url=" + secret); got != secret {
				t.Fatalf("FindSecrets() = %q, want %q", got, secret)
			}
		})
	}
}

func TestConcurrentLoadAndFind(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := LoadRules(); err != nil {
				t.Error(err)
				return
			}
			if got := FindSecrets("--password=example"); got != "--password=example" {
				t.Errorf("FindSecrets() = %q", got)
			}
		})
	}
	wg.Wait()
}

func TestInvalidRuleReturnsError(t *testing.T) {
	if _, err := compileRules([]byte("patterns:\n  - pattern:\n      name: broken\n      regex: '['\n")); err == nil {
		t.Fatal("invalid regex must return an error, not crash or be silently ignored")
	}
}
