package secretsengine

import (
	_ "embed"
	"fmt"
	"regexp"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yml
var rulesYAML []byte

var compiledRules []Rule
var loadOnce sync.Once
var loadErr error

type Rule struct {
	Name       string
	Re         *regexp.Regexp
	Confidence string
}

// LoadRules publishes an immutable rule set, safe to share between scan workers.
func LoadRules() error {
	loadOnce.Do(func() {
		compiledRules, loadErr = compileRules(rulesYAML)
	})
	return loadErr
}

func compileRules(data []byte) ([]Rule, error) {
	var root struct {
		Patterns []struct {
			Pattern struct {
				Name       string `yaml:"name"`
				Regex      string `yaml:"regex"`
				Confidence string `yaml:"confidence"`
			} `yaml:"pattern"`
		} `yaml:"patterns"`
	}

	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	raw := root.Patterns
	rules := make([]Rule, 0, len(raw))

	for _, r := range raw {
		re, err := regexp.Compile(r.Pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid secret rule %q: %w", r.Pattern.Name, err)
		}
		rules = append(rules, Rule{
			Name:       r.Pattern.Name,
			Re:         re,
			Confidence: r.Pattern.Confidence,
		})
	}

	return rules, nil
}

func FindSecrets(text string) string {
	if LoadRules() != nil {
		return ""
	}
	for _, rule := range compiledRules {
		// Capturing groups may be optional protocol fragments, not credentials.
		if match := rule.Re.FindString(text); match != "" {
			return match
		}
	}
	return ""
}
