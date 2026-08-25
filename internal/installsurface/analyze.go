// Package installsurface statically analyzes a package's install-time surface:
// the lifecycle hooks it declares, the files and URLs those hooks reach for, and
// the capabilities that chain exhibits.
//
// ZERO EXECUTION (Decision D-04). Nothing here runs a hook, a shell, or a
// package manager. It reads text and pattern-matches. The output is FACTS about
// what the install-time chain *can* touch — judging those facts is the VC-002
// family's job (Decision D-03).
//
// The static ceiling is deliberate and documented: this detects capability and
// indirection, NOT payload semantics. A hook that base64-decodes and evals a
// blob is reported as obfuscated+exec — we do not decode and reason about the
// payload. Detecting the obfuscation IS the finding.
package installsurface

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/pep508"
)

// Capability is something an install-time chain can do.
type Capability string

const (
	CapNetwork     Capability = "network"     // reaches the network
	CapCredentials Capability = "credentials" // touches NAMED secrets/tokens/credential files
	CapEnv         Capability = "env"         // reads process env generally (weak signal, very common)
	CapExec        Capability = "exec"        // spawns processes or evals code
	CapObfuscation Capability = "obfuscation" // base64/hex decode paired with code execution
	CapFilesystem  Capability = "filesystem"  // touches shell profiles / persistence locations
	CapCradle      Capability = "cradle"      // fetches remote code and executes it in one step
)

// InstallHookNames are the npm lifecycle scripts that run as part of an install.
// These are the ones that matter pre-install; `prepare` is included because npm
// runs it for git/dep installs.
var InstallHookNames = []string{
	"preinstall", "install", "postinstall",
	"preprepare", "prepare", "postprepare",
	"prepublish",
}

// PyPIInstallHookNames are synthetic hook names for Python install-time entry
// points. Unlike npm, Python has no declarative hook manifest — setup.py IS the
// hook. These names label the sections of setup.py that execute at install time.
var PyPIInstallHookNames = []string{
	"setup.py:module-level",
	"setup.py:cmdclass.install",
	"setup.py:cmdclass.develop",
	"setup.py:cmdclass.build_ext",
	"setup.py:cmdclass.egg_info",
	"pyproject.toml:build-backend",
	"pth:import",
}

// IsInstallHook reports whether a script name is an install-time lifecycle hook.
func IsInstallHook(name string) bool {
	for _, h := range InstallHookNames {
		if h == name {
			return true
		}
	}
	return false
}

// Artifact is a file or URL an install-time chain reaches for.
type Artifact struct {
	Ref      string       // local path (relative to package root) or absolute URL
	Remote   bool         // true when Ref is a URL
	Caps     []Capability // capabilities found in this artifact's own source
	Evidence []string     // human-readable markers that produced Caps
	Read     bool         // true when the artifact's source was available and scanned
}

// Sink is a credential/secret destination the chain references.
type Sink struct {
	Name     string // e.g. "NPM_TOKEN", "~/.npmrc"
	Evidence string
}

// Hook is one lifecycle hook and everything statically reachable from it.
type Hook struct {
	Name      string // preinstall, postinstall, ...
	Command   string // the raw script command
	Caps      []Capability
	Evidence  []string
	Artifacts []Artifact
	Sinks     []Sink
}

// HasCap reports whether the hook or any of its artifacts exhibits c.
func (h Hook) HasCap(c Capability) bool {
	for _, x := range h.Caps {
		if x == c {
			return true
		}
	}
	for _, a := range h.Artifacts {
		for _, x := range a.Caps {
			if x == c {
				return true
			}
		}
	}
	return false
}

// Surface is a package's complete install-time surface.
type Surface struct {
	Hooks []Hook
}

// FileReader returns the contents of a path relative to the package root.
// ok is false when the file is unavailable (not installed, outside the package,
// unreadable) — an unavailable file is recorded as unread, never guessed at.
type FileReader func(relPath string) (content []byte, ok bool)

// ---- pattern tables -------------------------------------------------------

var (
	urlRe = regexp.MustCompile(`https?://[^\s'"` + "`" + `)\\;|]+`)

	// script file references, e.g. "node setup.mjs", "sh ./install.sh"
	fileRefRe = regexp.MustCompile(`(?:^|[\s;&|])\.?/?([\w./@-]+\.(?:m?js|cjs|ts|sh|bash|py|ps1))`)

	networkMarkers = []string{
		"curl ", "wget ", "fetch(", "node-fetch", "axios", "https.get", "http.get",
		"https.request", "http.request", "XMLHttpRequest", "net.connect",
		"tls.connect", "dgram", "new WebSocket", "WebSocket(", "undici", "got(",
		// Python
		"urllib.request", "urllib2", "http.client", "httplib.", "import httplib",
		"urlopen(", "urlretrieve(", "requests.get", "requests.post",
		"httpx.", "aiohttp.Client", "import aiohttp", "ftplib", "smtplib", "socket.connect",
		// Ruby
		"Net::HTTP", "open-uri", "URI.open", "Faraday", "HTTParty",
		"RestClient", "Typhoeus", "Excon", "Net::FTP", "Net::SMTP",
		// Rust
		"reqwest::", "hyper::", "ureq::", "surf::", "TcpStream::connect",
		// PHP
		"file_get_contents(", "curl_exec(", "fopen(\"http", "fsockopen(",
		"stream_socket_client(", "guzzle",
		// PowerShell / .NET
		"Invoke-WebRequest", "Invoke-RestMethod", "System.Net.WebClient",
		"HttpClient", "DownloadString", "DownloadFile",
		// Windows LOLBin download cradles
		"finger.exe", "certutil", "bitsadmin", "msiexec",
	}

	// NAMED credential markers only. `process.env` alone is deliberately NOT
	// here: legitimate native-build hooks (node-gyp / prebuild-install and the
	// packages that depend on them) routinely read env vars AND fetch prebuilt
	// binaries. Treating broad env access as "credentials" would flag sharp,
	// bcrypt, sqlite3 and friends — the exact warning tax that gets a tool
	// muted (brief §6). Broad env access is recorded as CapEnv instead.
	credentialMarkers = []string{
		"NPM_TOKEN", "NODE_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
		".npmrc", ".git-credentials", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY",
		".aws/credentials", "KUBECONFIG", ".kube/config", "VAULT_TOKEN",
		"DOCKER_AUTH_CONFIG", ".docker/config.json", "SSH_PRIVATE_KEY", "id_rsa",
		".ssh/id_", "authorized_keys", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
		// cloud instance-metadata endpoints: an install hook reaching these is
		// reaching for cloud credentials (A.I.G recon/SSRF-to-creds). These are the
		// cheap bare-host backstop; imdsRe (run on raw source before URL stripping)
		// is the real fix for the common urlopen("http://169.254.169.254/…") shape.
		"169.254.169.254", "metadata.google.internal", "metadata.azure.com",
		"STRIPE_SECRET", "SLACK_TOKEN", "HF_TOKEN", "OPENAI_API_KEY",
		// Python
		".pypirc", "PYPI_TOKEN", "TWINE_PASSWORD", "TWINE_USERNAME",
		"POETRY_PYPI_TOKEN", "CONDA_TOKEN", ".netrc",
		// Ruby
		"GEM_HOST_API_KEY", ".gem/credentials",
		// Rust
		"CARGO_REGISTRY_TOKEN", "CRATES_TOKEN",
		// PHP
		"COMPOSER_AUTH", "PACKAGIST_TOKEN",
		// NuGet / .NET
		"NUGET_API_KEY", "NUGET_AUTH_TOKEN",
	}

	envMarkers = []string{
		"process.env", "os.environ", "getenv(",
		"os.getenv(", "platform.node(", "socket.gethostname(", "socket.getfqdn(", ".getsockname(",
		"getpass.getuser(", "uuid.getnode(",
		// Ruby
		"ENV[", "ENV.fetch",
		// Rust
		"env::var(", "env::vars(",
		// PHP
		"getenv(", "$_ENV[", "$_SERVER[",
		// PowerShell
		"$env:", "Get-ChildItem Env:",
	}

	execMarkers = []string{
		"child_process", "execSync", "spawnSync", "execFile",
		"eval(", "new Function(", "vm.runIn", "| sh", "|sh", "| bash", "|bash",
		"require('child", `require("child`,
		// Python
		"os.system(", "os.popen(", "subprocess.", "exec(",
		"compile(", "__import__(", "ctypes.", "importlib.", "runpy.",
		// Ruby
		"system(", "Kernel.exec", "IO.popen", "Open3.", "`",
		"Kernel.system", "%x{", "%x(",
		// Rust
		"Command::new", "process::Command",
		// PHP
		"exec(", "shell_exec(", "passthru(", "system(",
		"proc_open(", "popen(",
		// PowerShell. The call operator "&" is NOT a plain substring marker: bare
		// "& " (ampersand-space) matches shell "&& " and a trailing background "&",
		// which are ubiquitous in benign hooks (npm install && npm run build), so it
		// gave every such hook an incidental CapExec. It is detected structurally by
		// psCallOperatorRe instead (OPU-27 follow-up).
		"Start-Process", "Invoke-Expression", "iex ",
		// Windows LOLBins (code execution / app-whitelisting bypass)
		"mshta", "regsvr32", "cscript", "wscript",
	}

	// Obfuscation markers are decode-specific. Bare `Buffer.from(` is excluded:
	// it is ubiquitous in benign code. A base64/hex DECODE is the signal.
	//
	// Bare `fromCharCode` was removed (Decision D-25): a single incidental
	// String.fromCharCode(x) — formatting one byte — is not obfuscation, and it
	// false-flagged esbuild's installer as VC-002e. Char-code ASSEMBLY (a payload
	// built from many codes, or via .apply/.map) is detected structurally below.
	obfuscationMarkers = []string{
		"atob(", "unescape(", "decodeURIComponent(escape",
		// Python
		"codecs.decode(", "binascii.unhexlify(", "marshal.loads(",
		"pickle.loads(", "zlib.decompress(", "bz2.decompress(",
		"lzma.decompress(",
		// Ruby
		"Base64.decode64", "Marshal.load", "Zlib::Inflate",
		// PHP
		"base64_decode(", "gzuncompress(", "gzinflate(", "str_rot13(",
		"convert_uudecode(",
		// PowerShell
		"FromBase64String", "Decompress", "-EncodedCommand",
	}

	// base64/hex decode idioms, matched structurally rather than by substring.
	//
	// OPU-33: the hex alternative used to be a bare `['"]hex['"]\s*\)` — it
	// matched the string "hex")" ANYWHERE, including .digest('hex') and
	// .toString('hex'), which ENCODE bytes to a hex string for display or
	// comparison (the thing a security-conscious installer should do), not
	// decode one. esbuild's install.js does exactly this
	// (crypto.createHash(...).digest("hex")) and tripped VC-002e on it —
	// confirmed pre-existing (predates OPU-32, commit 570eb395/initial
	// release) via an OPU-32 FP sweep. Tightened to the same
	// context-required shape the base64 alternative already uses:
	// Buffer.from(...,'hex') is a real decode; from_?hex/hex::decode cover
	// the Rust-style naming convention already present for base64 below.
	decodeRe = regexp.MustCompile(`(?i)(Buffer\.from\s*\([^)]*['"]base64['"]|from_?base64|b64decode|Buffer\.from\s*\([^)]*['"]hex['"]|from_?hex|hex::decode|toString\s*\(\s*['"]utf-?8['"]\s*\)|base64\.b64decode|base64\.decodebytes|base64::decode|base64::engine|general_purpose::[A-Za-z_]+\.decode)`)

	// A long unbroken base64-ish run — the classic embedded blob.
	blobRe = regexp.MustCompile(`[A-Za-z0-9+/=]{160,}`)

	// Char-code ASSEMBLY: String.fromCharCode building a payload rather than
	// formatting a single byte (Decision D-25). Matches the .apply form
	// (fromCharCode.apply(null, arr)), three-or-more literal codes
	// (fromCharCode(0x68, 0x74, ...)), or a map/reduce/forEach over fromCharCode.
	// A lone fromCharCode(x) — the benign incidental case — matches none of these.
	charCodeAssemblyRe = regexp.MustCompile(`(?i)(?:fromCharCode\.apply|fromCharCode\s*\([^)]*,[^)]*,|(?:map|reduce|forEach)\s*\([^)]*fromCharCode)`)

	// C-family comments. URLs and capability markers sitting in DOCUMENTATION
	// must not be read as behavior — the defect that made esbuild's installer
	// "reach" snapcraft.io and nodejs.org, both of which live in a comment block
	// explaining the Snap Store (Decision D-25).
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`(?m)(^|[^:])//[^\n]*`)

	// A download CRADLE (Decision D-28): remote code fetched and executed in one
	// breath. This is deliberately NARROWER than "network + exec" — esbuild
	// fetches from a known host and runs a *shipped* prebuilt binary, which is
	// not a cradle. A cradle is the initial-access idiom that legitimate
	// installers do not use: piping a download straight into an interpreter, or
	// a living-off-the-land binary used to pull and run code.
	cradleRe = regexp.MustCompile(`(?i)` +
		// curl/wget/fetch ... | sh|bash|python|perl|ruby|node|pwsh ...
		`(?:curl|wget|fetch|lynx|links|iwr|invoke-webrequest)\b[^|\n]*\|\s*(?:sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node|pwsh|powershell|cmd)\b` +
		// (New-Object Net.WebClient).DownloadString(...) | iex  — and the reverse
		`|(?:downloadstring|downloaddata|webclient)[^\n]*\|\s*(?:iex|invoke-expression)` +
		`|(?:iex|invoke-expression)\b[^\n]*(?:downloadstring|downloaddata|webclient|invoke-webrequest)` +
		// LOLBin download cradles
		`|certutil\b[^\n]*-(?:urlcache|decode|f)\b` +
		`|bitsadmin\b[^\n]*/transfer\b`)

	// Caret or single-char separator obfuscation of URL schemes:
	// h^t^t^p^s, h.t.t.p, h+t+t+p+s, "h"+"t"+"t"+"p", etc.
	obfuscatedSchemeRe = regexp.MustCompile(`(?i)h[^a-z0-9]{1,3}t[^a-z0-9]{1,3}t[^a-z0-9]{1,3}p(?:[^a-z0-9]{1,3}s)?`)

	// Wildcard-obfuscated executable names (ClickFix-style evasion):
	// c*u*r*l.e?e, p*ell.exe, p*w*e*r*s*h*e*l*l, c*d.e?e
	wildcardExeRe = regexp.MustCompile(`(?i)(?:c\*u\*r\*l|p\*(?:ow)?\*?e\*?r?\*?(?:sh)?\*?ell|p\*ell|c\*d\.e|c\*m\*d)`)

	// cmd.exe delayed expansion — enables !var! substitution for evasion.
	delayedExpansionRe = regexp.MustCompile(`(?i)/v:on\b`)

	// OPU-32 (BRIDGEHEAD, Aug 2026): a byte XORed against a key-derived byte
	// and fed straight into fromCharCode. Functionally a decode — this is
	// literally how the BRIDGEHEAD dropper unpacked its C2 URL and PowerShell
	// bridge — but it shares no tokens with the base64/hex markers above and
	// matches none of the three charCodeAssemblyRe shapes: it is ONE
	// fromCharCode call per loop iteration (a hand-rolled cipher loop), not an
	// assembled batch. Gated on the `^` appearing INSIDE the fromCharCode
	// argument list so an incidental XOR used for something unrelated
	// (checksum math, RNG mixing) elsewhere in the file does not match.
	xorCharCodeRe = regexp.MustCompile(`(?i)fromCharCode\s*\([^)]*\^[^)]*\)`)

	// OPU-32: async fetch-then-exec cradle. cradleRe (D-28) only matches
	// single-line shell/PowerShell pipe idioms (`curl ... | sh`), which don't
	// exist in a JS-native installer. BRIDGEHEAD's native-Windows branch
	// fetches with a callback and spawns from INSIDE that callback instead of
	// a shell pipe: `https.get(url, () => spawn(dest))`.
	//
	// OPU-34: the original version bounded the window at the next `;`, which
	// excludes a callback with more than one statement before the actual
	// spawn — the norm, not the exception, confirmed on 2 of 3 real 2026
	// campaigns tested (Mastra/easy-day-js, a dependency-confusion cluster).
	// A first fix tried widening to a flat character count instead, but
	// character distance is NOT a reliable proxy: the same esbuild shape
	// (Decision D-28's stated FP target) sits 294 characters apart in the
	// existing condensed regression fixture and 1,544 characters apart in
	// the real 300-line file — no single window threshold survives both.
	//
	// The real distinguishing signal is structural, not distance-based:
	// esbuild's exec call always lives inside a separately-declared NAMED
	// function (`function installUsingNPM(...) {`/`function validate(...)
	// {`), reached only because that function is called elsewhere — it is
	// never inside the fetch call's own anonymous callback. Mastra and the
	// dependency-confusion cluster nest everything as anonymous arrows
	// directly inside the original callback; no named function declaration
	// ever sits between the callback and the spawn. asyncCradleCandidateRe
	// finds the candidate span (generously bounded, since distance itself
	// no longer needs to do the discriminating work); the Go loop below
	// rejects any candidate whose captured span contains a named function
	// declaration.
	asyncCradleCandidateRe = regexp.MustCompile(`(?is)(?:https?\.(?:get|request)|fetch|axios\.(?:get|post))\s*\([\s\S]{0,80}?(?:=>|function)([\s\S]{0,1000}?)(?:spawn|execFile|execFileSync|child_process\.exec)\s*\(`)

	// A NAMED function declaration — `function foo(...)`, name required.
	// An anonymous callback (`function(res) {...}` or `(res) => {...}`) does
	// NOT match this: only a genuinely separate, independently-invoked
	// function does, which is exactly the esbuild-vs-Mastra distinction.
	namedFunctionDeclRe = regexp.MustCompile(`\bfunction\s+[A-Za-z_$][\w$]*\s*\(`)

	// OPU-32: a spawned scripting interpreter (powershell, cmd, wscript,
	// cscript, mshta). On its own this is just CapExec — legitimate installers
	// occasionally shell out to one of these. It only becomes a cradle signal
	// in combination with CapObfuscation below (decode-then-invoke-interpreter),
	// which is checked after this text has been fully scanned.
	//
	// OPU-34: the original version only matched spawn/spawnSync with the
	// interpreter as an ISOLATED literal argument (spawn('powershell.exe',
	// ...)). Real malware (axios/plain-crypto-js, March 2026) invokes via
	// execSync with a shell COMMAND-LINE STRING containing the interpreter
	// name as a substring (execSync(`cscript.exe //nologo //B "..."`)) —
	// wrong function name AND wrong argument shape, both missed. Broadened
	// to the full exec family and to matching the interpreter as a
	// whole-word token anywhere within the first quoted/backtick argument,
	// not just as that argument's entire content. Still requires the
	// argument to open with a quote/backtick immediately (allowing only
	// whitespace before it) — a variable-built command
	// (`exec(command, ...)` where `command` was assembled elsewhere, e.g.
	// sudo-prompt's real `command.push('powershell.exe')` pattern) does not
	// match; that further indirection is a known residual gap, not
	// something this fix claims to close.
	interpreterSpawnRe = regexp.MustCompile(`(?i)(?:spawn(?:Sync)?|exec(?:Sync|File(?:Sync)?)?)\s*\(\s*[` + "`" + `'"][^` + "`" + `'"]{0,200}\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?)\b`)

	// psCallOperatorRe detects the PowerShell CALL operator — a single `&` that
	// invokes a command by quoted path, scriptblock, or variable (`& "C:\p.exe"`,
	// `& {…}`, `& $payload`, and the no-space `&"p.exe"`/`&$payload` forms). It
	// deliberately excludes the shell logical-AND `&&` and a trailing background
	// `&`: the leading `[^&]` rules out the second `&` of `&&`, and the required
	// following `['"{$]` rules out `&& cmd` and `cmd & other` (which the old bare
	// `"& "` substring marker matched, giving `npm install && npm run build` a
	// spurious CapExec). A bare `& word` is left unmatched: it is ambiguous with
	// shell backgrounding, and the dangerous PowerShell shapes are quoted/variable
	// invocations, already covered here, or the iex/Start-Process markers above.
	psCallOperatorRe = regexp.MustCompile(`(?:^|[^&])&\s*['"{$]`)

	// persistenceMarkers are filesystem locations that AUTO-EXECUTE on boot or
	// login — shell profiles, cron, systemd/launchd services, the Windows Startup
	// folder, the PowerShell $PROFILE. A library's install hook essentially never
	// installs one of these; that is an OS-package/admin action, not a build step
	// (A.I.G SkillTrustBench T06). VC-002g gates on exactly this set. They are
	// CapFilesystem like any other install write, so Part A's capability output is
	// unchanged — the persistence/benign split lives in the marker taxonomy, read
	// by the check via IsPersistenceMarker, not in a new capability.
	persistenceMarkers = []string{
		".bashrc", ".bash_profile", ".zshrc", ".profile",
		"crontab", "systemd", "systemctl", "launchctl", "launchd",
		// macOS auto-run dirs, listed explicitly so word-boundary matching (below)
		// still covers them once bare "launchd" stops matching inside them.
		"LaunchDaemons", "LaunchAgents",
		// The Windows Startup FOLDER (matched precisely by startupFolderRe below,
		// emitted as the "startup-folder" marker). A bare "startup" substring was
		// removed: it matched benign identifiers and prose — coverage.py's
		// `process_startup()` .pth and a "on startup" comment in setuptools'
		// setup.py both tripped VC-002g HIGH in the OpenShell live-fire.
		// PowerShell / .NET
		"$PROFILE", "Microsoft.PowerShell",
		// VCS-event auto-execution (OPU-27): an install hook that redirects the
		// git hook path or writes into a .git/hooks dir is arranging code to run
		// on a future git event. DELIBERATELY these two explicit shapes only —
		// bare `husky` / `husky install` is NOT listed, because it is the most
		// common prepare script in the ecosystem, runs only in a dev/git checkout
		// (never for a consumer's tarball install), and listing it would be the
		// warning tax the persistence-vs-benign split exists to avoid (OPU-19).
		"core.hooksPath", ".git/hooks/", ".git\\hooks\\",

		// AI-coding-agent / editor auto-run configuration (OPU-35/OPU-36): an
		// install hook writing any of these files into the consuming project
		// establishes auto-execution persistence that survives `npm uninstall`
		// entirely, since the files live in project config, not node_modules.
		// The full list below is the exact set the Miasma/Shai-Hulud worm family
		// used (JFrog Security Research, StepSecurity, Ossprey — June 2026,
		// corroborated by three independent analyses):
		//   .vscode/tasks.json     — VS Code task with runOn:folderOpen (OPU-35)
		//   .claude/settings.json  — Claude Code SessionStart hook (OPU-35)
		//   .claude/settings.local.json — ditto, local override (OPU-35)
		//   .cursor/rules/         — Cursor AI custom rules dir (alwaysApply:true)
		//   .cursorrules           — Cursor older single-file rules format
		//   .windsurfrules         — Windsurf IDE rules file
		//   .gemini/settings.json  — Google Gemini CLI settings
		//   .github/copilot-instructions.md — GitHub Copilot workspace instructions
		//   mcp.json               — MCP (Model Context Protocol) server config
		//   .aider.conf.yml        — Aider AI coding assistant config
		// The same FP-safety argument applies for all: this set only scans an
		// install hook's OWN source text (never the project tree), so a project's
		// own legitimately checked-in rules file never matches here.
		".vscode/tasks.json", ".claude/settings.json", ".claude/settings.local.json",
		// OPU-36: the remaining confirmed Miasma targets
		".cursor/rules/", ".cursorrules", ".windsurfrules",
		".gemini/settings.json", ".gemini/", ".github/copilot-instructions.md",
		"mcp.json", ".aider.conf.yml",
	}

	// claudeSettingsJoinRe / vscodeTasksJoinRe (OPU-35): the SAME two targets
	// above, constructed via path.join()-style adjacent quoted segments rather
	// than a single combined string — e.g.
	// path.join(cwd, '.claude', 'settings.json'). This is the idiomatic
	// Node.js path-construction style, arguably more common than a hardcoded
	// combined string, and the flat substring markers above miss it entirely:
	// confirmed empirically while validating this patch — a faithful
	// reproduction of the real Mini Shai-Hulud mechanism using
	// path.join(dir, '.claude', 'settings.json') did not fire until this was
	// added. Deliberately narrow: catches the two segments as sibling
	// arguments (the common case), not a variable holding the directory
	// constructed on an earlier line — that crosses a statement boundary this
	// static, zero-execution pass does not track (Decision D-04).
	claudeSettingsJoinRe = regexp.MustCompile(`(?i)['"]\.claude['"]\s*,\s*['"]settings(\.local)?\.json['"]`)
	vscodeTasksJoinRe    = regexp.MustCompile(`(?i)['"]\.vscode['"]\s*,\s*['"]tasks\.json['"]`)

	// cursorRulesJoinRe (OPU-36): .cursor/rules is a DIRECTORY, so the real
	// Miasma payload writes with three-segment path.join (e.g.
	// path.join(cwd, '.cursor', 'rules', 'setup.mdc')) — not two. Extend the
	// join-regex pattern to three sibling segments: match '.cursor' adjacent
	// to 'rules' with an optional third segment for the filename inside.
	cursorRulesJoinRe = regexp.MustCompile(`(?i)['"]\.cursor['"]\s*,\s*['"]rules['"]`)

	// installWriteMarkers are ordinary filesystem writes an install legitimately
	// makes (site-packages, .pth, gem dirs, locating the home directory). They are
	// CapFilesystem but must NOT raise VC-002g — flagging a site-packages write as
	// persistence would false-positive at exactly the rate the tool's discipline
	// avoids.
	installWriteMarkers = []string{
		"os.homedir()", "AppData\\Roaming",
		// Python
		"site-packages", "sysconfig.", "distutils.",
		"pathlib.Path.home(", ".pth",
		// Ruby
		"Gem.dir", "Gem.path", "spec.extensions",
		// PHP
		"vendor/autoload.php",
	}

	// imdsRe recognizes a cloud instance-metadata reach on the RAW source, before
	// URL stripping removes the host (Decision D-25 strips doc-URLs, but an IMDS URL
	// passed to urlopen is behavior, not documentation). An install hook reaching
	// IMDS is reaching for cloud credentials, so a match elevates to CapCredentials
	// — VC-002c, or VC-002d with egress — not a bland VC-002b network note.
	imdsRe = regexp.MustCompile(`(?i)169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|/latest/meta-data/`)

	// runnerTargetRe recognizes package RUNNERS that fetch-and-execute a package
	// from a registry in one step, across ecosystems (OPU-27 + Part E), and
	// captures the target package name (group 1) so each invocation can be judged
	// individually (Part D):
	//
	//	JS     npx, bunx, pnpm/yarn/bun dlx|x
	//	Python pipx run, uvx, uv tool run
	//	Ruby   gem exec (RubyGems 3.5+)
	//	.NET   dnx (the .NET 10 tool runner)
	//
	// Unlike `curl | sh`, this is not a shell cradle — it is the package manager's
	// own resolution path — so a scored invocation is CapNetwork + CapExec
	// (elevates to VC-002b), NOT CapCradle. The forms that run an ALREADY-installed
	// bin (`pnpm exec`, `yarn exec`, `bundle exec`, `dotnet tool run`, `composer
	// exec`, `poetry run`, `python -m`) match no branch — no fetch, no capability.
	// The prefix class includes the quote characters `'"` so a runner invoked from
	// a shell string inside setup.py / extconf.rb (`os.system('pipx run evil')`,
	// backtick `gem exec evil`) is caught, not only a bare command; the quote must
	// ABUT the keyword, which selects command-strings over prose that merely
	// mentions a runner. A trailing `@version` is not captured (`@` is outside the
	// target class), so `only-allow@2` yields target "only-allow".
	runnerTargetRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(='"` + "`" + `])(?:npx|bunx|uvx|dnx|(?:pnpm|yarn|bun)\s+(?:dlx|x)|pipx\s+run|uv\s+tool\s+run|gem\s+exec)\s+(?:--?\w[\w-]*\s+)*(@?[\w][\w.-]*(?:/[\w.-]+)?)`)

	// pkgRunnerOfflineRe suppresses a runner invocation that is explicitly pinned
	// to not fetch. `npx --no-install foo` / `npx --offline foo`, and `uvx
	// --offline` / `uv tool run --offline` (Part E), resolve only a local bin, so
	// the network capability does not apply. `pipx run` has no offline flag. It is
	// tested against each invocation's own matched substring (not the whole hook),
	// so an offline runner cannot suppress a second, network-reaching runner in the
	// same hook.
	pkgRunnerOfflineRe = regexp.MustCompile(`(?i)(?:npx|bunx|dlx|x|uvx|uv\s+tool\s+run)\s+(?:--?\w[\w-]*\s+)*(?:--no-install|--offline|--prefer-offline)\b`)

	// benignRunnerTargets is a curated, exact-match allowlist of runner target
	// packages that are known-benign guard clauses — they gate WHICH package
	// manager may install and contribute no payload (OPU-27 Part D). `only-allow`
	// is the canonical one (`npx only-allow pnpm` as a preinstall): it inspects
	// npm_config_user_agent and exits, nothing more. A runner whose every target
	// is on this list is disclosed (a `benign-runner:` evidence marker) but raises
	// no capability, mirroring the husky exclusion but data-driven. The match is
	// EXACT (distance-0): a typosquat like `only-alow` is not on the list and
	// scores normally, and the list stays deliberately tiny — a guard clause is a
	// narrow, well-known shape, and every entry is warning-tax the tool foregoes,
	// so growth must clear the same bar `only-allow` does.
	benignRunnerTargets = []string{
		"only-allow",
	}

	// pkgInstallRe recognizes an install hook invoking a package MANAGER to
	// install code from a registry (OPU-27). A hook that runs `npm install -g
	// <x>`, `pip install <x>`, `gem install <x>`, `cargo install <x>` fetches and
	// runs third-party code at the consumer's install time — a real network reach
	// the current markers miss (smart-buffer/socks `npm install -g typescript`
	// scored exec-only). `npm run <script>` is NOT matched (no fetch); only the
	// install/add/ci subcommands are. This is CapNetwork; any exec is scored
	// separately by the exec markers. The prefix class carries the quote characters
	// `'"` (Part E) so an install invoked from a shell string inside setup.py /
	// extconf.rb (`os.system('pip install evil')`) is caught, not only a bare
	// command — the same boundary the non-npm analyzers need to fire, and the same
	// word-boundary precision (`xpip install` still does not match).
	pkgInstallRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(='"` + "`" + `])(?:` +
		`(?:npm|pnpm|yarn|bun)\s+(?:install|i|ci|add)\b` +
		`|pip[0-9.]*\s+install\b|python[0-9.]*\s+-m\s+pip\s+install\b` +
		`|gem\s+install\b|cargo\s+install\b|go\s+install\b|poetry\s+add\b|uv\s+(?:pip\s+install|add)\b` +
		`)`)

	// goRunRemoteRe recognizes `go run <module>@<version>` — Go's package RUNNER,
	// the npx analog (OPU-28 Increment 4). Since Go 1.17 a `go run` argument with a
	// `@version` suffix FETCHES and RUNS that remote module in one step (network +
	// exec); it most often rides a `//go:generate go run evil.example/cmd@latest`
	// directive. The `@version` is the discriminator and the run-vs-fetch line: Go
	// requires it to fetch, so `go run ./local`, `go run .`, and `go run main.go`
	// (local code, no fetch) carry no version and do not match — the same discipline
	// that keeps `pnpm exec` off the runner set. The prefix class carries `'"` so a
	// shell-string invocation is caught too.
	goRunRemoteRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(='"` + "`" + `])go[ \t]+run[ \t]+(?:-\S+[ \t]+)*[\w][\w./-]*@[\w][\w.+~-]*`)
)

// isBenignRunnerTarget reports whether a package RUNNER's target (the package it
// fetch-and-executes) is a known-benign guard clause on the exact-match allowlist
// (OPU-27 Part D). The comparison is case-insensitive but distance-0: a typosquat
// of an allowlisted name is not benign.
func isBenignRunnerTarget(name string) bool {
	for _, b := range benignRunnerTargets {
		if strings.EqualFold(name, b) {
			return true
		}
	}
	return false
}

// IsPersistenceMarker reports whether an install-surface evidence marker names a
// persistence mechanism (auto-executes on boot/login) as opposed to an ordinary
// install write. VC-002g uses it to gate on cron/service/profile/startup writes
// only, excluding benign site-packages/.pth/gem writes (OPU-19).
func IsPersistenceMarker(marker string) bool {
	// startup-folder is emitted by startupFolderRe (a precise Windows Startup
	// folder / shell:startup match), replacing the old bare "startup" substring.
	if strings.EqualFold(marker, "startup-folder") {
		return true
	}
	// /etc/ is emitted by etcAbsolutePathRe (D-131), replacing the old flat
	// substring entry that also matched a merely-nested "etc" path segment
	// (./etc/templates/, ./spec/etc/) with nothing to do with the real
	// absolute Unix system directory.
	if strings.EqualFold(marker, "/etc/") {
		return true
	}
	for _, m := range persistenceMarkers {
		if strings.EqualFold(marker, m) {
			return true
		}
	}
	return false
}

// stripCodeComments removes C-family block and line comments so that URLs and
// capability markers sitting in documentation are not mistaken for behavior
// (Decision D-25). It is a heuristic, not a tokenizer: the (^|[^:]) guard
// protects the "//" inside a URL scheme, and the only residual cost — a "//"
// inside a string literal — is under-citing a reference, never fabricating one.
func stripCodeComments(src string) string {
	src = blockCommentRe.ReplaceAllString(src, " ")
	src = lineCommentRe.ReplaceAllString(src, "$1")
	return src
}

// isIdentByte reports whether b is an identifier character (letter, digit, _).
func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// boundaryCheckedPunctuationMarkers are punctuation-anchored persistence
// markers (isWordMarker is false for them, since they contain non-identifier
// characters) that STILL need the dual-boundary containsWord check, unlike
// the rest of that class (.bashrc, .git/hooks/). Found via an FP sweep
// (D-130): ".profile" is simultaneously the shell dotfile AND the generic
// suffix of any object-property access — `user.profileImage`,
// `settings.profileData`, `options.profile` all contain the literal
// substring ".profile" with nothing to do with the dotfile technique. Unlike
// most punctuation-anchored markers, "profile" alone is a common enough
// identifier stem that "specific enough to stay a raw substring" does not
// hold. The real technique always writes/references ".profile" as a
// complete path component — preceded by a quote, path separator, or
// whitespace, followed by a quote, separator, whitespace, or end of string —
// never continued by, or continuing from, another identifier character,
// which is exactly what containsWord already checks on both sides for
// identifier-shaped markers. Costs nothing against the real technique.
var boundaryCheckedPunctuationMarkers = map[string]bool{
	".profile": true,
}

// etcAbsolutePathRe (D-131, same FP sweep as D-130): "/etc/" used to be a flat
// persistenceMarkers entry, matched as a raw substring — but that also fires
// on ANY path that merely nests a directory literally named "etc" without
// being the real absolute Unix system directory: `require('./etc/templates/
// config.js')`, `require('./spec/etc/config.js')`. containsWord's dual
// boundary check (the fix used for .profile above) does not fully close this:
// its "before" check only asks whether the PRECEDING byte is an identifier
// character, and "." and "/" both pass that test, so `./etc/` would still
// match. What actually distinguishes the real absolute path is stronger: the
// leading "/" of "/etc/" must be the START of a quoted string, shell token,
// or the whole source — never continued FROM another path segment (a "."
// or "/" immediately before it). Matched here as a whitelist of legitimate
// preceding characters (quote, backtick, whitespace, and the shell/JS
// argument separators ; & | ( = > < ,) rather than a blacklist, so a
// preceding character this list does not anticipate fails closed (excluded),
// not open. Deliberately does NOT try to distinguish a READ of /etc/ (e.g.
// fs.existsSync('/etc/os-release'), a common, legitimate OS/libc-detection
// idiom in native-module installers) from a WRITE establishing persistence —
// no other persistence marker in this list makes that distinction either
// (a bare `fs.existsSync('~/.bashrc')` also trips VC-002g today), so singling
// out /etc/ for read/write semantics would be inconsistent, not more correct.
var etcAbsolutePathRe = regexp.MustCompile(`(?:^|['"` + "`" + `\s;&|(=><,])/etc/`)

// isWordMarker reports whether a marker is a bare identifier-shaped token
// (letters/digits/_ only), which must be matched on word boundaries rather than
// as a raw substring so it does not fire inside a larger identifier.
func isWordMarker(m string) bool {
	if m == "" {
		return false
	}
	for i := 0; i < len(m); i++ {
		if !isIdentByte(m[i]) {
			return false
		}
	}
	return true
}

// containsWord reports whether word occurs in hay bounded by non-identifier
// characters (or the string edges) on both sides — a lightweight `\bword\b`.
// Both arguments are expected pre-lowercased.
func containsWord(hay, word string) bool {
	if word == "" {
		return false
	}
	for from := 0; ; {
		i := strings.Index(hay[from:], word)
		if i < 0 {
			return false
		}
		i += from
		beforeOK := i == 0 || !isIdentByte(hay[i-1])
		after := i + len(word)
		afterOK := after >= len(hay) || !isIdentByte(hay[after])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

// scanCaps classifies a blob of text (a command line or a file's source).
func scanCaps(text string) ([]Capability, []string) {
	var caps []Capability
	var ev []string
	add := func(c Capability, marker string) {
		for _, x := range caps {
			if x == c {
				ev = append(ev, marker)
				return
			}
		}
		caps = append(caps, c)
		ev = append(ev, marker)
	}

	lower := strings.ToLower(text)
	scan := func(markers []string, c Capability) {
		for _, m := range markers {
			if strings.Contains(lower, strings.ToLower(m)) {
				add(c, m)
			}
		}
	}
	scan(networkMarkers, CapNetwork)
	scan(credentialMarkers, CapCredentials)
	scan(envMarkers, CapEnv)
	scan(execMarkers, CapExec)
	scan(obfuscationMarkers, CapObfuscation)
	// Persistence and ordinary install writes are both CapFilesystem; the
	// persistence/benign distinction lives in the marker (IsPersistenceMarker),
	// read by VC-002g, so the capability output is unchanged (OPU-19).
	// Identifier-shaped persistence markers (systemd, crontab, launchd, ...) match
	// on WORD BOUNDARIES so they do not fire inside a larger token — `systemd` no
	// longer matches the mkwinsyscall `-systemdll` flag (a beats live-fire FP),
	// nor `crontab` inside `crontabber`. Punctuation-anchored markers (.bashrc,
	// /etc/, .git/hooks/) are specific enough to stay raw substring matches —
	// except boundaryCheckedPunctuationMarkers (D-130), which need the same
	// dual-boundary check despite containing punctuation.
	for _, m := range persistenceMarkers {
		lm := strings.ToLower(m)
		matched := strings.Contains(lower, lm)
		if matched && (isWordMarker(m) || boundaryCheckedPunctuationMarkers[m]) {
			matched = containsWord(lower, lm)
		}
		if matched {
			add(CapFilesystem, m)
		}
	}
	scan(installWriteMarkers, CapFilesystem)
	// The Windows Startup FOLDER, matched precisely (shell:startup, or a
	// ...\Programs\Startup path) rather than the bare word "startup", which
	// over-matched benign identifiers/prose (process_startup, "on startup").
	if startupFolderRe.MatchString(text) {
		add(CapFilesystem, "startup-folder")
	}
	// A genuinely absolute /etc/ path (D-131) — not a merely-nested "etc"
	// directory segment inside a relative path (./etc/, ./spec/etc/).
	if etcAbsolutePathRe.MatchString(text) {
		add(CapFilesystem, "/etc/")
	}
	// path.join()-split forms of the AI-agent-hook persistence targets
	// (OPU-35): emits the SAME canonical marker string the flat substring
	// match above would, so IsPersistenceMarker recognizes either shape
	// identically — VC-002g does not need to know which form matched. The
	// settings-vs-settings.local distinction (group 1) is preserved in the
	// emitted marker so a finding's evidence names the file that was
	// actually written, not always the non-local variant.
	if m := claudeSettingsJoinRe.FindStringSubmatch(text); m != nil {
		if m[1] != "" {
			add(CapFilesystem, ".claude/settings.local.json")
		} else {
			add(CapFilesystem, ".claude/settings.json")
		}
	}
	if vscodeTasksJoinRe.MatchString(text) {
		add(CapFilesystem, ".vscode/tasks.json")
	}
	// path.join() split form for .cursor/rules (OPU-36): three-segment join
	// pattern (.cursor + rules + filename) that the flat marker misses.
	if cursorRulesJoinRe.MatchString(text) {
		add(CapFilesystem, ".cursor/rules/")
	}

	// A URL anywhere is a network reach even without a named client.
	if urlRe.MatchString(text) {
		add(CapNetwork, "url-literal")
	}
	// Structural decode idioms and embedded blobs.
	if m := decodeRe.FindString(text); m != "" {
		add(CapObfuscation, "decode:"+strings.TrimSpace(m))
	}
	if blobRe.MatchString(text) {
		add(CapObfuscation, "long-encoded-blob")
	}
	// Char-code assembly (payload built from many codes), not incidental use.
	if m := charCodeAssemblyRe.FindString(text); m != "" {
		add(CapObfuscation, "charcode-assembly:"+strings.TrimSpace(m))
	}
	// Download-and-execute cradle (D-28).
	if m := cradleRe.FindString(text); m != "" {
		add(CapCradle, "download-cradle:"+strings.TrimSpace(m))
	}
	// Caret/separator-obfuscated URL schemes: h^t^t^p^s, "h"+"t"+"t"+"p", etc.
	if m := obfuscatedSchemeRe.FindString(text); m != "" {
		add(CapObfuscation, "obfuscated-scheme:"+m)
		add(CapNetwork, "obfuscated-scheme:"+m)
	}
	// Wildcard-obfuscated executables: c*u*r*l.e?e, p*ell.exe
	if m := wildcardExeRe.FindString(text); m != "" {
		add(CapObfuscation, "wildcard-exe:"+m)
		add(CapExec, "wildcard-exe:"+m)
	}
	// cmd delayed expansion: /v:on enables !var! for evasion
	if delayedExpansionRe.MatchString(text) {
		add(CapObfuscation, "cmd-delayed-expansion")
	}
	// PowerShell call operator (`& "path"`, `& {block}`, `& $var`): code
	// execution, distinguished structurally from shell `&&` / background `&`.
	if m := psCallOperatorRe.FindString(text); m != "" {
		add(CapExec, "ps-call-operator:"+strings.TrimSpace(m))
	}
	// Package RUNNER (npx / pnpm dlx / yarn dlx / bunx): fetch-and-execute a
	// registry package in one step — network + exec at the consumer's install
	// time (OPU-27). Judged PER INVOCATION so a benign or offline runner cannot
	// launder a hostile one in the same hook: each invocation that is neither
	// explicitly offline nor a known-benign guard-clause target (Part D) scores
	// CapNetwork + CapExec on its own target name.
	for _, m := range runnerTargetRe.FindAllStringSubmatch(text, -1) {
		invocation, target := m[0], m[1]
		if pkgRunnerOfflineRe.MatchString(invocation) {
			continue // pinned offline: resolves a local bin, no network reach
		}
		if isBenignRunnerTarget(target) {
			// Disclosed but not scored: a known package-manager guard clause runs
			// at install but carries no payload (Part D). No capability raised.
			ev = append(ev, "benign-runner:"+target)
			continue
		}
		add(CapNetwork, "pkg-runner:"+target)
		add(CapExec, "pkg-runner:"+target)
	}
	// Package MANAGER install (npm/pnpm/yarn/bun install|add|ci, pip/gem/cargo/go
	// install, ...): fetches third-party code from a registry at install time
	// (OPU-27). Network only; exec, if present, is scored by the exec markers.
	if m := pkgInstallRe.FindString(text); m != "" {
		add(CapNetwork, "pkg-install:"+strings.TrimSpace(m))
	}
	// Go package RUNNER: `go run <module>@<version>` fetches AND runs a remote
	// module in one step — network + exec, the npx analog (OPU-28 Increment 4).
	if m := goRunRemoteRe.FindString(text); m != "" {
		add(CapNetwork, "pkg-runner:"+strings.TrimSpace(m))
		add(CapExec, "pkg-runner:"+strings.TrimSpace(m))
	}
	// XOR-keyed decode idiom (OPU-32): a byte XORed with a key-derived byte,
	// fed straight into fromCharCode. See xorCharCodeRe above.
	if m := xorCharCodeRe.FindString(text); m != "" {
		add(CapObfuscation, "xor-charcode:"+strings.TrimSpace(m))
	}
	// Async fetch-then-exec cradle (OPU-32, structural filter added
	// OPU-34): a network fetch whose own callback spawns a process — the
	// JS-native analog of `curl ... | sh`. Reject any candidate whose span
	// crosses into a separately-declared named function (see
	// namedFunctionDeclRe above) — that signals the exec call belongs to
	// an unrelated function, not this fetch's own callback.
	for _, m := range asyncCradleCandidateRe.FindAllStringSubmatch(text, -1) {
		if namedFunctionDeclRe.MatchString(m[1]) {
			continue
		}
		add(CapCradle, "async-cradle:"+strings.TrimSpace(m[0][:min(len(m[0]), 80)]))
		break
	}
	// Decode-then-invoke-interpreter (OPU-32): obfuscation immediately feeding
	// a spawned script interpreter is a cradle even when the decoded command
	// itself is not statically resolvable. BRIDGEHEAD's WSL branch is exactly
	// this shape: the actual fetch-and-run only exists inside a PowerShell
	// string assembled at runtime from four decoded fragments, so it never
	// appears as literal source text for cradleRe or asyncCradleRe to match.
	// This does not decode or reason about that string (Decision D-04) — it
	// scores the co-occurrence of "this hook decodes something" and "this hook
	// hands a decoded value to a script interpreter" as itself the finding.
	if interpreterSpawnRe.MatchString(text) {
		for _, c := range caps {
			if c == CapObfuscation {
				add(CapCradle, "decode-then-interpreter-spawn")
				break
			}
		}
	}
	return caps, dedupe(ev)
}

// findSinks extracts credential targets referenced in text.
func findSinks(text string) []Sink {
	var out []Sink
	seen := map[string]bool{}
	lower := strings.ToLower(text)
	for _, m := range credentialMarkers {
		if strings.Contains(lower, strings.ToLower(m)) && !seen[m] {
			seen[m] = true
			out = append(out, Sink{Name: m, Evidence: "referenced in install-time source"})
		}
	}
	return out
}

// Analyze builds the install surface from a package's scripts map. read supplies
// the source of locally referenced files; it may be nil (then referenced files
// are recorded as unread rather than guessed at).
//
// Traversal depth is bounded at one level (hook -> referenced file). Deeper
// chains are represented by the first-level artifact; the bound is explicit
// rather than silent.
func Analyze(scripts map[string]string, read FileReader) Surface {
	var s Surface
	// Deterministic order: iterate the known hook list, not the map.
	for _, name := range InstallHookNames {
		cmd, ok := scripts[name]
		if !ok || strings.TrimSpace(cmd) == "" {
			continue
		}
		h := Hook{Name: name, Command: cmd}
		h.Caps, h.Evidence = scanCaps(cmd)
		h.Sinks = findSinks(cmd)

		// Remote artifacts referenced directly by the command.
		for _, u := range dedupe(urlRe.FindAllString(cmd, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true, Read: false})
		}

		// Local files the command executes.
		for _, m := range fileRefRe.FindAllStringSubmatch(cmd, -1) {
			ref := strings.TrimPrefix(m[1], "./")
			if ref == "" || isKnownBinaryName(ref) {
				continue
			}
			a := Artifact{Ref: ref}
			if read != nil {
				if src, ok := read(ref); ok {
					a.Read = true
					// Strip comments first: a URL or marker in documentation is
					// not behavior (Decision D-25).
					clean := stripCodeComments(string(src))
					a.Caps, a.Evidence = scanCaps(clean)
					h.Sinks = append(h.Sinks, findSinks(clean)...)
					// URLs inside the referenced file become remote artifacts.
					for _, u := range dedupe(urlRe.FindAllString(clean, -1)) {
						h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
					}
				}
			}
			h.Artifacts = append(h.Artifacts, a)
		}
		h.Sinks = dedupeSinks(h.Sinks)
		s.Hooks = append(s.Hooks, h)
	}
	return s
}

// isKnownBinaryName filters interpreter names that the regex may catch.
func isKnownBinaryName(ref string) bool {
	switch ref {
	case "node.js", "npm.js":
		return true
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupeSinks(in []Sink) []Sink {
	seen := map[string]bool{}
	var out []Sink
	for _, s := range in {
		if !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- Load-time (import-time) analysis (OPU-31) ------------------------------

// loadTimeRefRe extracts quoted RELATIVE paths a module references (e.g. the
// bundled binary a loader spawns): 'new URL("./math-core.bin", import.meta.url)'
// or join(__dirname, "./internal/calc.dat"). Absolute paths and bare specifiers
// (npm deps) are intentionally not matched — only files shipped alongside the
// entry.
var loadTimeRefRe = regexp.MustCompile(`['"](\.\.?/[^'"\n]+)['"]`)

// startupFolderRe matches the Windows Startup FOLDER precisely — a
// `shell:startup` (or `shell:common startup`) reference, or a
// ...\Programs\Startup path — so VC-002g persistence gates on a real autostart
// location rather than the bare word "startup" (which matched process_startup,
// "on startup", startup-time, etc.).
var startupFolderRe = regexp.MustCompile(`(?i)shell:(?:common )?startup|programs[\\/]+startup`)

// jsLoadTimeExecRe matches a GENUINE JavaScript/TypeScript execution capability
// reachable at import: a process-spawning module, or dynamic code evaluation. It
// deliberately omits the shell / multi-language substring markers scanCaps
// carries — a template-literal backtick, a regex `.exec(`, a `system(` substring,
// a lone `spawn(` — which fire on ordinary bundled library code and fabricated
// load-time hooks on buffer / ms / lru-cache / mqtt / @meshtastic/core in the
// meshclaw live-fire. A real loader is still matched, including the RedC2 shape
// (`node:child_process` + a bundled binary) that motivated load-time analysis.
var jsLoadTimeExecRe = regexp.MustCompile(`(?i)child_process|\beval\s*\(|new\s+Function\s*\(|\bvm\.runin|node:vm|require\(\s*['"]vm['"]`)

// jsLoadTimeNetworkRe matches genuine JS network reach: a bare global fetch(
// (NOT a `.fetch(` method call such as lru-cache's cache.fetch()), an
// http/https/net/tls/dgram/http2 module, a WebSocket / XMLHttpRequest, or a known
// HTTP client. URL literals are handled separately by the caller.
var jsLoadTimeNetworkRe = regexp.MustCompile(`(?i)(?:^|[^.\w])fetch\s*\(|node:(?:http|https|net|tls|dgram|http2)|require\(\s*['"](?:https?|net|tls|dgram|http2|node-fetch|axios|got|undici)['"]|xmlhttprequest|new\s+websocket`)

// loadTimeExecJS reports whether an entry module has a real JS execution surface:
// a process-spawn / dynamic-eval capability, or one of the precise STRUCTURAL
// exec signals scanCaps already resolves (a package runner, a wildcard-obscured
// exe, the PowerShell call operator, a download cradle). The ambiguous substring
// exec markers are ignored here — that is the whole point of the JS-context gate.
func loadTimeExecJS(clean string, ev []string) bool {
	if jsLoadTimeExecRe.MatchString(clean) {
		return true
	}
	for _, e := range ev {
		// Only structural signals that are genuinely suspicious IN JS count here.
		// A PowerShell call operator (`ps-call-operator:"&"`) matches a JS bitwise
		// `&` / minified operator (mqtt's bundle: `&":"`, `&"env"`), and a package
		// runner needs child_process to actually run (already covered above) — both
		// are shell/PS constructs that FP on JS, so they are excluded.
		if strings.HasPrefix(e, "wildcard-exe:") || strings.HasPrefix(e, "download-cradle:") {
			return true
		}
	}
	return false
}

// loadTimeNetworkJS reports whether an entry module has a real JS network reach.
func loadTimeNetworkJS(clean string) bool {
	return jsLoadTimeNetworkRe.MatchString(clean) || urlRe.MatchString(clean)
}

// dropCap returns caps without c, and evidence without the given false-positive
// markers (used to strip a method-fetch network signal from a load-time hook).
func dropCap(caps []Capability, c Capability, ev []string, fpMarkers ...string) ([]Capability, []string) {
	out := caps[:0:0]
	for _, x := range caps {
		if x != c {
			out = append(out, x)
		}
	}
	if len(fpMarkers) == 0 {
		return out, ev
	}
	drop := map[string]bool{}
	for _, m := range fpMarkers {
		drop[m] = true
	}
	kept := ev[:0:0]
	for _, e := range ev {
		if !drop[e] {
			kept = append(kept, e)
		}
	}
	return out, kept
}

// AnalyzeLoadTime builds the install surface from a package's ENTRY MODULE — the
// file a require()/import loads. Analyze() is seeded by package.json lifecycle
// scripts; a package with NO such script can still run a payload the moment it
// is imported, even transitively, from its main/entry module. That is exactly
// how the RedC2 npm loader evades lifecycle-script analysis: dist/index.mjs
// re-exports the promised helpers and, at module load, marks a bundled binary
// executable and spawns it detached — no install hook, no exported function
// (OPU-31). This scans the entry's top level for execution capability and, when
// present, records a load-time hook; a referenced sibling file carrying native
// executable magic is surfaced as the bundled-binary payload. Nothing is
// executed (D-04).
//
// entryRel is the entry's package-relative path (for evidence and to resolve
// sibling references); entrySource is its content; read resolves sibling files
// relative to the package root.
func AnalyzeLoadTime(entryRel, entrySource string, read FileReader) Surface {
	var s Surface
	clean := stripCodeComments(entrySource)
	if strings.TrimSpace(clean) == "" {
		return s
	}
	caps, ev := scanCaps(clean)
	// The load-time context is JS/TS library code, where scanCaps' shell /
	// multi-language exec markers over-fire (a template literal, a regex
	// `.exec(`, a `.fetch(` method, a `system(` substring). Gate on a JS-precise
	// execution signal so those do not fabricate a load-time hook — the
	// warning-tax false-positive class the meshclaw live-fire surfaced — while a
	// genuine loader (child_process / eval / Function / vm, or a package runner)
	// still passes.
	if !loadTimeExecJS(clean, ev) {
		return s
	}
	// A method call named fetch (e.g. lru-cache's cache.fetch()) is not network
	// reach; drop the capability when no real JS network signal is present so a
	// legitimate loader is not mislabeled as reaching the network at import.
	if containsCap(caps, CapNetwork) && !loadTimeNetworkJS(clean) {
		caps, ev = dropCap(caps, CapNetwork, ev, "fetch(")
	}
	h := Hook{
		Name:     "module-load:" + entryRel,
		Command:  "entry module executes at import (no lifecycle hook required): " + entryRel,
		Caps:     caps,
		Evidence: appendStr(ev, "load-time-execution"),
		Sinks:    findSinks(clean),
	}
	// Remote code/data fetched at load time.
	for _, u := range dedupe(urlRe.FindAllString(clean, -1)) {
		h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
	}
	// Sibling files the entry references, resolved relative to the entry's dir.
	// A referenced NATIVE EXECUTABLE spawned at import is the payload half of the
	// loader pattern — the composition (load-time exec + bundled native binary)
	// is the RedC2 fingerprint.
	entryDir := ""
	if i := strings.LastIndexByte(entryRel, '/'); i >= 0 {
		entryDir = entryRel[:i]
	}
	seen := map[string]bool{}
	for _, m := range loadTimeRefRe.FindAllStringSubmatch(clean, -1) {
		ref := strings.TrimPrefix(m[1], "./")
		if ref == "" || seen[ref] || len(seen) >= 16 {
			continue
		}
		seen[ref] = true
		full := ref
		if entryDir != "" {
			full = entryDir + "/" + ref
		}
		if read == nil {
			continue
		}
		body, ok := read(full)
		if !ok {
			continue
		}
		art := Artifact{Ref: ref, Read: true}
		if kind, native := nativeExecutableKind(body); native {
			art.Caps = appendUnique(art.Caps, CapExec)
			art.Evidence = appendStr(art.Evidence, "bundled-native-executable:"+kind)
			h.Evidence = appendStr(h.Evidence, "bundled-native-executable:"+kind)
		}
		h.Artifacts = append(h.Artifacts, art)
	}
	h.Sinks = dedupeSinks(h.Sinks)
	s.Hooks = append(s.Hooks, h)
	return s
}

// containsCap reports whether caps includes c.
func containsCap(caps []Capability, c Capability) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// nativeExecutableKind classifies a file's leading magic bytes as a native
// executable format. Stdlib-only (D-10), reads only the first bytes. The
// 0xcafebabe case also matches a Java class file; in an npm package spawned at
// import that is itself noteworthy, so it is reported as mach-o/fat.
func nativeExecutableKind(b []byte) (string, bool) {
	if len(b) < 4 {
		return "", false
	}
	if b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return "elf", true
	}
	if b[0] == 0x4d && b[1] == 0x5a { // "MZ" — PE/DOS
		return "pe", true
	}
	switch uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca:
		return "mach-o", true
	}
	return "", false
}

// ---- Ruby analysis ----------------------------------------------------------

// RubyInstallHookNames are hook names for Ruby gem install-time execution.
var RubyInstallHookNames = []string{
	"extconf.rb",
	"Rakefile:compile",
}

// rakeCompileRe detects a Rakefile declaring a native-extension compile task
// (rake-compiler convention) — an ordinary Rakefile with neither is not an
// install-time hook, matching the gemspec:extensions branch's discipline.
var rakeCompileRe = regexp.MustCompile(`(?i)Rake::(?:Extension|Compiler)Task|task\s+[:'"]compile\b|require\s+['"]rake/extensiontask['"]`)

// AnalyzeRuby builds the install surface from a Ruby gem's build files.
// extconfRb is the content of extconf.rb (may be empty). gemspec is the
// content of the .gemspec file (may be empty). rakefile is the content of the
// gem's Rakefile (may be empty).
func AnalyzeRuby(extconfRb, gemspec, rakefile string) Surface {
	var s Surface
	if extconfRb != "" {
		caps, ev := scanCaps(extconfRb)
		caps = appendUnique(caps, CapExec)
		ev = appendStr(ev, "extconf.rb")
		h := Hook{
			Name:     "extconf.rb",
			Command:  truncateStr(extconfRb, 400),
			Caps:     caps,
			Evidence: ev,
			Sinks:    findSinks(extconfRb),
		}
		for _, u := range dedupe(urlRe.FindAllString(extconfRb, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
		}
		s.Hooks = append(s.Hooks, h)
	}
	if rakefile != "" && rakeCompileRe.MatchString(rakefile) {
		caps, ev := scanCaps(rakefile)
		caps = appendUnique(caps, CapExec)
		ev = appendStr(ev, "Rakefile:compile")
		h := Hook{
			Name:     "Rakefile:compile",
			Command:  truncateStr(rakefile, 400),
			Caps:     caps,
			Evidence: ev,
			Sinks:    findSinks(rakefile),
		}
		for _, u := range dedupe(urlRe.FindAllString(rakefile, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
		}
		s.Hooks = append(s.Hooks, h)
	}
	if gemspec != "" {
		if strings.Contains(gemspec, "extensions") && strings.Contains(gemspec, "extconf") {
			caps, ev := scanCaps(gemspec)
			if len(caps) > 0 {
				s.Hooks = append(s.Hooks, Hook{
					Name:     "gemspec:extensions",
					Command:  "gemspec declares native extensions",
					Caps:     caps,
					Evidence: ev,
				})
			}
		}
	}
	return s
}

// ---- Rust analysis ----------------------------------------------------------

// RustInstallHookNames are hook names for Rust build-time execution.
var RustInstallHookNames = []string{
	"build.rs",
	"proc-macro",
}

// AnalyzeRust builds the install surface from a Rust crate's build files.
// buildRs is the content of build.rs (may be empty).
func AnalyzeRust(buildRs string) Surface {
	var s Surface
	if buildRs == "" {
		return s
	}
	caps, ev := scanCaps(buildRs)
	caps = appendUnique(caps, CapExec)
	ev = appendStr(ev, "build.rs")
	h := Hook{
		Name:     "build.rs",
		Command:  truncateStr(buildRs, 400),
		Caps:     caps,
		Evidence: ev,
		Sinks:    findSinks(buildRs),
	}
	for _, u := range dedupe(urlRe.FindAllString(buildRs, -1)) {
		h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
	}
	s.Hooks = append(s.Hooks, h)
	return s
}

// ---- Go analysis ------------------------------------------------------------

// GoInstallHookNames labels the Go build-surface execution points OPU-28 extracts.
// Go, uniquely, runs NO package code at `go get` / `go build` by design — its
// closest analog to a lifecycle script is the go:generate directive, which ships
// an arbitrary command that runs when a developer invokes `go generate`.
var GoInstallHookNames = []string{
	"go:generate",
}

// goGenerateRe matches a `//go:generate <command>` directive and captures the
// command. Go requires the directive comment to have NO space between `//` and
// `go:generate`; cmd/go tolerates leading indentation, so optional leading
// whitespace is accepted. The command is the rest of the line (trailing
// whitespace trimmed); `.` does not cross newlines, so a directive stays on its
// own line.
var goGenerateRe = regexp.MustCompile(`(?m)^[ \t]*//go:generate[ \t]+(.+?)[ \t]*$`)

var (
	// cgoImportRe reports that a file actually enables cgo — the `import "C"` line,
	// standalone or inside an import group. Only such files have live `#cgo`
	// directives; requiring it keeps a stray `#cgo`-shaped comment or string in a
	// non-cgo file from being read as a build flag.
	cgoImportRe = regexp.MustCompile(`(?m)^[ \t]*(?:import[ \t]+)?"C"[ \t]*(?:$|//)`)

	// cgoDirectiveRe matches a single `#cgo …` preamble directive line (e.g.
	// `#cgo CFLAGS: -O2`, `#cgo linux LDFLAGS: -ldl`, `#cgo pkg-config: gtk+-3.0`).
	// The preamble may be written as a block comment (`/* #cgo … */`, where the
	// directive line begins with `#cgo`) OR as line comments (`// #cgo …`), both
	// equally valid cgo syntax; the optional `//` prefix accepts the latter so a
	// plugin-load injection in a line-comment preamble is not missed.
	cgoDirectiveRe = regexp.MustCompile(`(?m)^[ \t]*(?://[ \t]*)?#cgo\b[^\n]*`)

	// The dangerous-flag detectors. A `#cgo` directive normally carries only inert
	// compiler/linker flags (-I, -L, -l, -D, -std=, -Wall, pkg-config names). These
	// match the shapes that instead arrange CODE EXECUTION at `go build` time, none
	// of which a legitimate published module ships:
	//   - a compiler/LLVM plugin load (runs attacker code inside the compiler)
	cgoPluginRe = regexp.MustCompile(`(?i)-fplugin\b|-Xclang\b|(?:^|[ \t])-load\b`)
	//   - a GCC specs-file override (redirects the whole compilation)
	cgoSpecsRe = regexp.MustCompile(`(?i)-specs=`)
	//   - a -B tool-search-path redirect (runs the attacker's as/ld instead)
	cgoToolDirRe = regexp.MustCompile(`(?:^|[ \t])-B[ =/]`)
	//   - an @file response file (smuggles otherwise-rejected flags)
	cgoResponseRe = regexp.MustCompile(`(?:^|[ \t,])@[^ \t]`)
	//   - a shell metacharacter (command injection into the build). Note `${SRCDIR}`
	//     — the legitimate cgo source-dir variable — uses `${…}`, NOT `$(`, so it is
	//     deliberately not matched.
	cgoShellRe = regexp.MustCompile("[;|`]|\\$\\(")
)

// AnalyzeGo builds the install surface from a Go module's source files (OPU-28).
// sources maps a file path (used only to label the hook) to that .go file's text.
//
// Increment 1 extracts `//go:generate` directives. A go:generate command runs
// when a developer invokes `go generate` — NOT at `go build` or `go get`, which
// execute no package code (this is Go's deliberate design, and the finding text
// says so). It is nonetheless the strongest "arbitrary command shipped in a
// package" shape Go offers, and `go generate ./...` is a routine dev/CI step, so
// a hostile directive in a dependency is weaponizable. The command is classified
// by the shared scanCaps engine, so a benign generator (`mockgen`, `stringer`,
// `go run ./internal/gen`) exhibits no capability and is not recorded, while a
// network fetch or a `curl | sh` cradle raises the matching VC-002 finding.
//
// cgo `#cgo` flag injection (build-time) and build-tag-gated init evasion
// (runtime) are a later increment.
func AnalyzeGo(sources map[string]string) Surface {
	var s Surface
	files := make([]string, 0, len(sources))
	for f := range sources {
		files = append(files, f)
	}
	sort.Strings(files) // deterministic hook order (D-09 byte-reproducibility)

	for _, file := range files {
		src := sources[file]
		directives := goGenerateRe.FindAllStringSubmatch(src, -1)
		for i, m := range directives {
			cmd := strings.TrimSpace(m[1])
			if cmd == "" {
				continue
			}
			caps, ev := scanCaps(cmd)
			// Only surface a directive that actually reaches the network, executes
			// remote code, or obfuscates — a benign local generator carries no
			// capability and is not a finding (the run-vs-fetch discipline, applied
			// to codegen). This also keeps a module full of benign go:generate
			// directives from cluttering the graph with inert hook nodes.
			if len(caps) == 0 {
				continue
			}
			name := "go:generate:" + file
			if len(directives) > 1 {
				name = fmt.Sprintf("go:generate:%s#%d", file, i+1)
			}
			h := Hook{
				Name:     name,
				Command:  truncateStr(cmd, 400),
				Caps:     caps,
				Evidence: appendStr(ev, "go:generate"),
				Sinks:    findSinks(cmd),
			}
			for _, u := range dedupe(urlRe.FindAllString(cmd, -1)) {
				h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
			}
			s.Hooks = append(s.Hooks, h)
		}

		// cgo `#cgo` flag injection (OPU-28 Increment 2): a build directive that
		// arranges code execution at `go build`. Only examined in files that enable
		// cgo, and only the DANGEROUS flag shapes — a directive of ordinary flags is
		// silent, keeping the check off the very common benign cgo package.
		if h, ok := analyzeCgoDirectives(file, src); ok {
			s.Hooks = append(s.Hooks, h)
		}

		// build-tag-gated init evasion (OPU-28 Increment 3): startup code hidden
		// behind a build constraint, carrying a network/decode/credential capability.
		if h, ok := analyzeConstrainedInit(file, src); ok {
			s.Hooks = append(s.Hooks, h)
		}
	}
	return s
}

// analyzeCgoDirectives inspects a cgo file's `#cgo` preamble directives and, when
// any carries a code-execution flag shape (plugin load, tool-search redirect,
// specs override, response file, or shell metacharacter), returns a hook recording
// it as CapExec with `cgo-inject:<reason>` markers that VC-002h gates on. A file
// with no `import "C"`, or whose directives are ordinary compiler/linker flags,
// returns ok=false.
func analyzeCgoDirectives(file, src string) (Hook, bool) {
	if !cgoImportRe.MatchString(src) {
		return Hook{}, false
	}
	var reasons, offending []string
	for _, line := range cgoDirectiveRe.FindAllString(src, -1) {
		found := cgoInjectionReasons(line)
		if len(found) > 0 {
			reasons = append(reasons, found...)
			offending = append(offending, strings.TrimSpace(line))
		}
	}
	if len(reasons) == 0 {
		return Hook{}, false
	}
	ev := []string{"cgo"}
	for _, r := range dedupe(reasons) {
		ev = append(ev, "cgo-inject:"+r)
	}
	return Hook{
		Name:     "cgo:" + file,
		Command:  truncateStr(strings.Join(offending, " ; "), 400),
		Caps:     []Capability{CapExec},
		Evidence: ev,
	}, true
}

// cgoInjectionReasons returns the code-execution flag shapes present in one `#cgo`
// directive line, as stable reason words (comma-free, so they survive the
// comma-joined evidence encoding VC-002h re-splits).
func cgoInjectionReasons(line string) []string {
	var out []string
	if cgoPluginRe.MatchString(line) {
		out = append(out, "plugin")
	}
	if cgoSpecsRe.MatchString(line) {
		out = append(out, "specs")
	}
	if cgoToolDirRe.MatchString(line) {
		out = append(out, "tool-redirect")
	}
	if cgoResponseRe.MatchString(line) {
		out = append(out, "response-file")
	}
	if cgoShellRe.MatchString(line) {
		out = append(out, "shell")
	}
	return out
}

// IsCgoInjectionMarker reports whether an install-surface evidence marker names a
// cgo build-flag code-execution shape (OPU-28). VC-002h gates on it, the same way
// VC-002g gates on IsPersistenceMarker.
func IsCgoInjectionMarker(marker string) bool {
	return strings.HasPrefix(marker, "cgo-inject:")
}

var (
	// goBuildTagRe / goLegacyBuildTagRe match an explicit build constraint (the
	// modern `//go:build expr` and the legacy `// +build expr`). A file carrying
	// one is conditionally compiled — it evades a default-build review, test run,
	// and CI on a non-matching platform/tag.
	goBuildTagRe       = regexp.MustCompile(`(?m)^//go:build[ \t]+(.+?)[ \t]*$`)
	goLegacyBuildTagRe = regexp.MustCompile(`(?m)^// \+build[ \t]+(.+?)[ \t]*$`)

	// goInitFuncRe / goBlankVarInitRe match the two package-level shapes that run
	// code automatically at program startup: `func init()` and a blank-identifier
	// var whose initializer is a CALL (`var _ = doThing()`) — the latter a known
	// evasion that avoids the more conspicuous init(). A blank var with a TYPE
	// (`var _ io.Reader = ...`, an interface assertion) has text between `_` and
	// `=`, so it is deliberately not matched.
	goInitFuncRe     = regexp.MustCompile(`(?m)^func[ \t]+init[ \t]*\([ \t]*\)`)
	goBlankVarInitRe = regexp.MustCompile(`(?m)^var[ \t]+_[ \t]*=[ \t]*[\w.]+\(`)

	// goGOOS / goGOARCH are the platform tokens a filename suffix (`net_linux.go`,
	// `asm_amd64.go`, `sys_linux_arm64.go`) encodes as an implicit build constraint.
	goGOOS = map[string]bool{
		"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true,
		"hurd": true, "illumos": true, "ios": true, "js": true, "linux": true,
		"netbsd": true, "openbsd": true, "plan9": true, "solaris": true, "wasip1": true,
		"windows": true, "zos": true,
	}
	goGOARCH = map[string]bool{
		"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true,
		"mips": true, "mips64": true, "mips64le": true, "mipsle": true, "ppc64": true,
		"ppc64le": true, "riscv64": true, "s390x": true, "sparc64": true, "wasm": true,
	}
)

// analyzeConstrainedInit reports a build-tag-gated init EVASION (OPU-28 Increment
// 3): a conditionally-compiled file whose startup code (init / blank-var call)
// carries a network, download-cradle, decode-obfuscation, or credential
// capability. All three must hold — a bare init(), an unconstrained file, or a
// constrained platform file that merely registers a driver stays silent, which is
// what keeps this off the very common benign build-tagged Go file.
//
// A runtime init is NOT an install hook, so no install-hook capability is exposed
// (Caps is nil); the facts ride evidence markers `init-constraint:<what>` and
// `init-cap:<reason>` that the dedicated VC-002i judge reads. Test files are
// skipped — their init runs only under `go test`, never in a consumer's binary.
func analyzeConstrainedInit(file, src string) (Hook, bool) {
	if strings.HasSuffix(pathBase(file), "_test.go") {
		return Hook{}, false
	}
	constraint, ok := goBuildConstraint(file, src)
	if !ok {
		return Hook{}, false
	}
	if !goInitFuncRe.MatchString(src) && !goBlankVarInitRe.MatchString(src) {
		return Hook{}, false
	}
	caps, _ := scanCaps(stripCodeComments(initScanText(src)))
	reasons := dangerousInitReasons(caps)
	if len(reasons) == 0 {
		return Hook{}, false
	}
	ev := []string{"init-constraint:" + constraint}
	for _, r := range reasons {
		ev = append(ev, "init-cap:"+r)
	}
	return Hook{
		Name:     "init:" + file,
		Command:  "build-constrained startup code (" + constraint + ")",
		Caps:     nil, // a runtime init is not an install-hook capability (VC-002i judges it)
		Evidence: ev,
	}, true
}

// initScanText returns the source that AUTO-RUNS at import — the init() bodies and
// package-level var initializers, plus every local function transitively reachable
// from them by a direct call — so a build-constrained-init finding is judged on
// what the startup path reaches, not on capabilities sitting in unrelated,
// explicitly-invoked functions elsewhere in the file. That whole-file attribution
// was the elastic-agent magefile false positive: an init() that only registers
// mage targets, in a file that (in separate targets) has network + credentials.
//
// It falls back to the full source — never a blind spot — when the file cannot be
// parsed, or when a higher-order dispatch shape is present (a LOCAL function
// receiving a LOCAL function VALUE, which it may invoke at import). An external
// registrar receiving a function value (mage's common.RegisterCheckDeps) is
// register-for-later and does NOT force the fallback, which is what clears the FP.
func initScanText(src string) string {
	if reachable, ok := initReachableSource(src); ok {
		return reachable
	}
	return src
}

func initReachableSource(src string) (string, bool) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return "", false // unparseable -> conservative whole-file scan
	}

	local := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name != nil && fd.Body != nil {
			local[fd.Name.Name] = fd // over-approx: methods indexed by name too (safe)
		}
	}

	// Import-time roots: init() bodies and package-level var initializers.
	var roots []ast.Node
	for _, d := range f.Decls {
		switch g := d.(type) {
		case *ast.FuncDecl:
			if g.Recv == nil && g.Name.Name == "init" && g.Body != nil {
				roots = append(roots, g.Body)
			}
		case *ast.GenDecl:
			if g.Tok == token.VAR {
				for _, s := range g.Specs {
					if vs, ok := s.(*ast.ValueSpec); ok {
						for _, v := range vs.Values {
							roots = append(roots, v)
						}
					}
				}
			}
		}
	}

	selName := func(e ast.Expr) string {
		switch fn := e.(type) {
		case *ast.Ident:
			return fn.Name
		case *ast.SelectorExpr:
			return fn.Sel.Name
		}
		return ""
	}
	argIsLocalFunc := func(a ast.Expr) bool {
		_, ok := local[selName(a)]
		return ok
	}

	reached := map[string]bool{}
	nodes := append([]ast.Node{}, roots...)
	work := append([]ast.Node{}, roots...)

	for len(work) > 0 {
		n := work[0]
		work = work[1:]
		fellBack := false
		ast.Inspect(n, func(x ast.Node) bool {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := selName(call.Fun)
			fd, isLocal := local[name]
			if isLocal {
				// A local callee receiving a local function VALUE may invoke it at
				// import; scanning only the callee's body could miss that payload,
				// so widen to the whole file (blind-spot guard).
				for _, a := range call.Args {
					if argIsLocalFunc(a) {
						fellBack = true
						return false
					}
				}
				if !reached[name] {
					reached[name] = true
					nodes = append(nodes, fd.Body)
					work = append(work, fd.Body)
				}
			}
			return true
		})
		if fellBack {
			return "", false
		}
	}

	var b strings.Builder
	for _, n := range nodes {
		s := fset.Position(n.Pos()).Offset
		e := fset.Position(n.End()).Offset
		if s >= 0 && e <= len(src) && s < e {
			b.WriteString(src[s:e])
			b.WriteByte('\n')
		}
	}
	return b.String(), true
}

// goBuildConstraint returns a short description of a file's build constraint, and
// whether it has one: an explicit `//go:build` / `// +build` tag (preferred), or a
// GOOS/GOARCH filename suffix.
func goBuildConstraint(file, src string) (string, bool) {
	if m := goBuildTagRe.FindStringSubmatch(src); m != nil {
		return "build-tag " + truncateStr(strings.TrimSpace(m[1]), 60), true
	}
	if m := goLegacyBuildTagRe.FindStringSubmatch(src); m != nil {
		return "build-tag " + truncateStr(strings.TrimSpace(m[1]), 60), true
	}
	return filenamePlatformConstraint(file)
}

// filenamePlatformConstraint reports the platform a file's `_GOOS`/`_GOARCH`/
// `_GOOS_GOARCH` suffix implies, and whether it has one.
func filenamePlatformConstraint(file string) (string, bool) {
	base := strings.TrimSuffix(pathBase(file), ".go")
	parts := strings.Split(base, "_")
	if len(parts) < 2 {
		return "", false
	}
	last := parts[len(parts)-1]
	if len(parts) >= 3 {
		if secondLast := parts[len(parts)-2]; goGOOS[secondLast] && goGOARCH[last] {
			return secondLast + "/" + last, true
		}
	}
	if goGOOS[last] {
		return last, true
	}
	if goGOARCH[last] {
		return last, true
	}
	return "", false
}

// dangerousInitReasons filters analyzed capabilities to the shapes that make an
// auto-running init suspicious: a network beacon, a download cradle, a decode of an
// embedded blob, or a credential read. Bare exec is deliberately excluded — a
// platform-specific file legitimately shells out to a system tool, and flagging
// that would tax normal cross-platform Go.
func dangerousInitReasons(caps []Capability) []string {
	want := map[Capability]string{
		CapNetwork:     "network",
		CapCradle:      "download-cradle",
		CapObfuscation: "decode-obfuscation",
		CapCredentials: "credentials",
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range caps {
		if r, ok := want[c]; ok && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// pathBase returns the last path component of a slash- or backslash-separated path,
// without importing path/filepath (this package keeps a minimal import footprint).
func pathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// IsInitEvasionMarker reports whether an evidence marker names a build-constrained
// startup-code capability (OPU-28 Increment 3). VC-002i gates on it, the same way
// VC-002g/h gate on their own marker predicates.
func IsInitEvasionMarker(marker string) bool {
	return strings.HasPrefix(marker, "init-cap:")
}

// ---- PHP/Composer analysis --------------------------------------------------

// ComposerInstallHookNames are lifecycle event names in Composer that execute
// during install/update.
var ComposerInstallHookNames = []string{
	"pre-install-cmd",
	"post-install-cmd",
	"pre-update-cmd",
	"post-update-cmd",
	"post-autoload-dump",
	"pre-autoload-dump",
}

// IsComposerInstallHook reports whether an event name runs at install time.
func IsComposerInstallHook(name string) bool {
	for _, h := range ComposerInstallHookNames {
		if h == name {
			return true
		}
	}
	return false
}

// AnalyzePHP builds the install surface from a Composer package's metadata.
// scripts maps event names to their command strings. pkgType is the package
// type from composer.json (empty string if unknown). pluginSource is the PHP
// source of the plugin's declared entrypoint class (empty when the package is
// not a plugin or the file could not be resolved).
//
// A composer-plugin is auto-loaded and its activate() runs on every Composer
// operation, so the plugin's own PHP is install-time code (Decision D-27). When
// its source is available it is scanned exactly like any other hook body; the
// bare-CapExec fallback stands when the source could not be read, so a plugin is
// never silently downgraded to "unknown".
func AnalyzePHP(scripts map[string]string, pkgType, pluginSource string) Surface {
	var s Surface

	if pkgType == "composer-plugin" {
		h := Hook{
			Name:     "composer-plugin",
			Command:  "package type is composer-plugin (auto-loaded at install time)",
			Caps:     []Capability{CapExec},
			Evidence: []string{"composer-plugin-type"},
		}
		if strings.TrimSpace(pluginSource) != "" {
			// Comment-strip first (Decision D-25): a URL or marker in PHP
			// documentation is not behavior.
			clean := stripCodeComments(pluginSource)
			pcaps, pev := scanCaps(clean)
			for _, c := range pcaps {
				h.Caps = appendUnique(h.Caps, c)
			}
			h.Evidence = append(h.Evidence, pev...)
			h.Sinks = findSinks(clean)
			for _, u := range dedupe(urlRe.FindAllString(clean, -1)) {
				h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
			}
		}
		s.Hooks = append(s.Hooks, h)
	}

	for _, name := range ComposerInstallHookNames {
		cmd, ok := scripts[name]
		if !ok || strings.TrimSpace(cmd) == "" {
			continue
		}
		h := Hook{Name: name, Command: cmd}
		h.Caps, h.Evidence = scanCaps(cmd)
		h.Sinks = findSinks(cmd)
		for _, u := range dedupe(urlRe.FindAllString(cmd, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
		}
		s.Hooks = append(s.Hooks, h)
	}
	return s
}

// ---- NuGet/.NET analysis ----------------------------------------------------

// NuGetInstallHookNames are PowerShell scripts that NuGet packages can include.
var NuGetInstallHookNames = []string{
	"install.ps1",
	"init.ps1",
	"uninstall.ps1",
}

// NuGetMSBuildDirs are the directories where NuGet packages can ship MSBuild
// .targets and .props files that execute at build time.
var NuGetMSBuildDirs = []string{
	"build",
	"buildTransitive",
	"buildMultiTargeting",
	"buildCrossTargeting",
}

// AnalyzeDotNet builds the install surface from a NuGet package's PowerShell
// install scripts. scripts maps filename to content.
func AnalyzeDotNet(scripts map[string]string) Surface {
	var s Surface
	for _, name := range NuGetInstallHookNames {
		content, ok := scripts[name]
		if !ok || strings.TrimSpace(content) == "" {
			continue
		}
		caps, ev := scanCaps(content)
		caps = appendUnique(caps, CapExec)
		ev = appendStr(ev, name)
		h := Hook{
			Name:     name,
			Command:  truncateStr(content, 400),
			Caps:     caps,
			Evidence: ev,
			Sinks:    findSinks(content),
		}
		for _, u := range dedupe(urlRe.FindAllString(content, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
		}
		s.Hooks = append(s.Hooks, h)
	}
	return s
}

// AnalyzeMSBuild builds the install surface from NuGet MSBuild .targets and
// .props files. These run arbitrary MSBuild targets at build time and can
// execute processes, download files, and modify the build. scripts maps
// relative path (e.g. "build/pkg.targets") to file content.
func AnalyzeMSBuild(scripts map[string]string) Surface {
	var s Surface
	for path, content := range scripts {
		if strings.TrimSpace(content) == "" {
			continue
		}
		caps, ev := scanCaps(content)
		caps = appendUnique(caps, CapExec)
		ev = appendStr(ev, "msbuild:"+path)
		h := Hook{
			Name:     path,
			Command:  truncateStr(content, 400),
			Caps:     caps,
			Evidence: ev,
			Sinks:    findSinks(content),
		}
		for _, u := range dedupe(urlRe.FindAllString(content, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
		}
		s.Hooks = append(s.Hooks, h)
	}
	return s
}

// AnalyzeProcMacro returns a surface for a Rust proc-macro crate. A proc-macro
// executes arbitrary code at compile time — it IS the hook. When the macro's
// source is available it is scanned for capabilities (network, credentials,
// obfuscation, etc.) so the VC-002 family can judge the risk. When the source
// is unavailable the surface records the structural fact with bare CapExec,
// which no VC-002 check gates on — the same false-positive discipline as
// composer-plugins.
func AnalyzeProcMacro(source string) Surface {
	h := Hook{
		Name:     "proc-macro",
		Command:  "crate is a proc-macro (executes at compile time)",
		Caps:     []Capability{CapExec},
		Evidence: []string{"proc-macro"},
	}
	if strings.TrimSpace(source) != "" {
		clean := stripCodeComments(source)
		caps, ev := scanCaps(clean)
		for _, c := range caps {
			h.Caps = appendUnique(h.Caps, c)
		}
		h.Evidence = append(h.Evidence, ev...)
		h.Sinks = findSinks(clean)
		for _, u := range dedupe(urlRe.FindAllString(clean, -1)) {
			h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
		}
	}
	return Surface{Hooks: []Hook{h}}
}

// ---- helpers ----------------------------------------------------------------

func appendUnique(caps []Capability, c Capability) []Capability {
	for _, x := range caps {
		if x == c {
			return caps
		}
	}
	return append(caps, c)
}

func appendStr(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

// ---- Python analysis --------------------------------------------------------

// cmdclassRe matches cmdclass dict entries that override install commands.
var cmdclassRe = regexp.MustCompile(`cmdclass\s*=\s*\{[^}]*\b(install|develop|build_ext|egg_info)\b`)

// cmdclassBlockRe extracts custom command class bodies for capability scanning.
var cmdclassBlockRe = regexp.MustCompile(`class\s+\w+\s*\([^)]*(?:install|develop|build_ext|egg_info)[^)]*\)\s*:`)

// AnalyzePython builds the install surface from a Python package's install-time
// files. setupPy is the full text of setup.py (may be empty). pyprojectToml is
// the full text of pyproject.toml (may be empty). pthFiles maps filename to
// content for any .pth files found in the distribution.
func AnalyzePython(setupPy, pyprojectToml string, pthFiles map[string]string) Surface {
	var s Surface

	if setupPy != "" {
		s.Hooks = append(s.Hooks, analyzeSetupPy(setupPy)...)
	}
	if pyprojectToml != "" {
		requires := ExtractBuildRequires(pyprojectToml)
		if h, ok := analyzeBuildBackend(pyprojectToml, setupPy != "", requires); ok {
			s.Hooks = append(s.Hooks, h)
		}
	}
	for name, content := range pthFiles {
		if h, ok := analyzePthFile(name, content); ok {
			s.Hooks = append(s.Hooks, h)
		}
	}
	return s
}

// setupDocStringRes strip the STRING-LITERAL value of setup()'s documentation
// metadata keywords (long_description / description) before capability scanning.
// These fields are inert package metadata — a string literal passed to setup()
// never executes — yet a README embedded as long_description routinely contains
// example code (`requests.get(...)`, `httpx.get()`, `curl ...`, `DownloadFile`)
// and tool names that are NOT install-time behavior. This was the beats live-fire
// VC-002b false positive on backoff / deprecated / pyasn1. Scoped deliberately to
// these two doc fields: an arbitrary string literal is NOT stripped (a shell
// command in `os.system("curl x | sh")` must still be scanned), and real egress
// in module-level code or a cmdclass body is untouched. RE2 has no backreferences,
// so each quote form is handled explicitly, triple-quoted first (a single-line
// pattern would otherwise close on the first quote inside a triple-quoted body).
// The key may be a keyword arg (`long_description=`) or a dict entry
// (`'long_description':`); `long_description_content_type` is not matched (the
// `\b` after the key fails before the `_`).
var setupDocStringRes = []*regexp.Regexp{
	regexp.MustCompile(`(?s)['"]?\b(?:long_description|description)\b['"]?\s*[:=]\s*[rbufRBUF]{0,2}""".*?"""`),
	regexp.MustCompile(`(?s)['"]?\b(?:long_description|description)\b['"]?\s*[:=]\s*[rbufRBUF]{0,2}'''.*?'''`),
	regexp.MustCompile(`['"]?\b(?:long_description|description)\b['"]?\s*[:=]\s*[rbufRBUF]{0,2}"(?:[^"\\\n]|\\.)*"`),
	regexp.MustCompile(`['"]?\b(?:long_description|description)\b['"]?\s*[:=]\s*[rbufRBUF]{0,2}'(?:[^'\\\n]|\\.)*'`),
}

// stripSetupDocStrings removes the doc-metadata string-literal values (see
// setupDocStringRes) so their prose cannot contribute capability markers.
// shellToolNetMarkers are network markers that are shell COMMANDS (LOLBins / CLI
// tools) rather than in-language client calls. They are egress only when actually
// run by a shell-exec sink; on their own (printed instructions, comments) they
// are inert.
var shellToolNetMarkers = map[string]bool{
	"curl ": true, "wget ": true, "certutil": true, "bitsadmin": true,
	"finger.exe": true, "msiexec": true,
}

// hasLibraryNetworkMarker reports whether any IN-LANGUAGE network client marker
// (urlopen(, requests.get, Net::HTTP, reqwest::, DownloadString, ...) — i.e. a
// networkMarker that is not a shell tool) is present.
func hasLibraryNetworkMarker(source string) bool {
	lower := strings.ToLower(source)
	for _, m := range networkMarkers {
		if shellToolNetMarkers[m] {
			continue
		}
		if strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

var shellExecSinkRe = regexp.MustCompile(`(?i)os\.system|subprocess|Popen|os\.popen|\bcommands\.getoutput|shell\s*=\s*true|\bexec\s*\(|\beval\s*\(`)

// hasShellExecSink reports whether source contains a way to run a shell command
// (os.system, subprocess, Popen, exec/eval, shell=True, ...).
func hasShellExecSink(source string) bool { return shellExecSinkRe.MatchString(source) }

// stripPyInert removes text that cannot execute — Python `#` comments and the
// module docstring — from setup.py source before capability scanning, so
// documentation is never mistaken for install-time behavior: a README rendered
// as __doc__ (long_description=__doc__), a `$ pip install X` line, a `wget ...`
// bootstrap comment, or RST backticks. It is string-aware — a `#` or keyword
// INSIDE a string literal (the command in os.system("curl x | sh")) is preserved
// — so real egress and download cradles still scan. Only the LEADING module
// docstring (a bare string as the first statement) is dropped; string VALUES
// (assignments, call args, dict entries) are kept, since those can be behavior.
func stripPyInert(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	i, n := 0, len(src)
	atStmtStart := true
	docstringDropped := false
	for i < n {
		c := src[i]
		// A string at statement start (optionally r/b/u/f-prefixed) is the module
		// docstring — inert (stored as __doc__, never executed), so drop it.
		if atStmtStart && !docstringDropped {
			if q := pyStringOpen(src, i); q >= 0 {
				i = scanPyString(src, q)
				docstringDropped = true
				atStmtStart = false
				continue
			}
		}
		switch {
		case c == '#':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			end := scanPyString(src, i)
			b.WriteString(src[i:end])
			i = end
			atStmtStart = false
		case c == '\n':
			b.WriteByte(c)
			i++
			atStmtStart = true
		case c == ' ' || c == '\t' || c == '\r':
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(c)
			i++
			atStmtStart = false
		}
	}
	return b.String()
}

// pyStringOpen returns the index of the opening quote if s at i begins a Python
// string literal (with up to two r/b/u/f prefix letters), else -1.
func pyStringOpen(s string, i int) int {
	j := i
	for j < i+2 && j < len(s) {
		c := s[j]
		if c == 'r' || c == 'R' || c == 'b' || c == 'B' || c == 'u' || c == 'U' || c == 'f' || c == 'F' {
			j++
			continue
		}
		break
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		return j
	}
	return -1
}

// scanPyString returns the index just past the Python string literal that begins
// at i, handling ' and " single- and triple-quoted forms and backslash escapes.
func scanPyString(s string, i int) int {
	n := len(s)
	q := s[i]
	if i+2 < n && s[i+1] == q && s[i+2] == q { // triple-quoted
		i += 3
		for i < n {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == q && i+2 < n && s[i+1] == q && s[i+2] == q {
				return i + 3
			}
			if s[i] == q && i+2 >= n { // closing triple at end of input
				if i+3 <= n && i+1 < n && s[i+1] == q && i+2 < n && s[i+2] == q {
					return i + 3
				}
			}
			i++
		}
		return n
	}
	i++ // past the opening quote
	for i < n {
		switch s[i] {
		case '\\':
			i += 2
		case q:
			return i + 1
		case '\n':
			return i // unterminated single-line string; stop at the newline
		default:
			i++
		}
	}
	return n
}

func stripSetupDocStrings(source string) string {
	for _, re := range setupDocStringRes {
		source = re.ReplaceAllString(source, "long_description=\"\"")
	}
	return source
}

// analyzeSetupPy extracts install-time hooks from setup.py. It identifies
// module-level side effects (code that runs before setup()) and custom cmdclass
// overrides (classes that replace pip's default install behavior).
func analyzeSetupPy(source string) []Hook {
	var hooks []Hook

	// Strip ALL URLs before capability scanning. In setup.py, URLs are
	// overwhelmingly metadata: README badges, homepage, project_urls, license
	// text, error messages, comments. Real network egress is detected by
	// function markers (urlopen, requests.get, curl, etc.) which fire
	// independently of the URL string. Only collect URL artifacts from lines
	// that also contain a network function call — those are actual targets.
	// The documentation metadata fields (long_description / description) are
	// stripped first: a README embedded there carries example code and tool
	// names that are metadata, not egress (beats live-fire VC-002b FP).
	cleaned := urlRe.ReplaceAllString(stripPyInert(stripSetupDocStrings(source)), "")

	allCaps, allEvidence := scanCaps(cleaned)
	// Shell-tool network words (curl/wget/certutil/...) are egress only if the
	// file can actually run a shell command. In setup.py they routinely appear in
	// printed instructions ("wget https://.../ez_setup.py") with no exec sink —
	// inert (pyasn1 VC-002b FP). Drop CapNetwork when its only basis is a
	// shell-tool word with no network-library CALL and no shell-exec sink present.
	if containsCap(allCaps, CapNetwork) && !hasLibraryNetworkMarker(cleaned) && !hasShellExecSink(cleaned) {
		allCaps, allEvidence = dropCap(allCaps, CapNetwork, allEvidence,
			"curl ", "wget ", "certutil", "bitsadmin", "finger.exe", "msiexec")
	}
	allSinks := findSinks(cleaned)
	// IMDS is almost always reached via a URL (urlopen("http://169.254.169.254/…")),
	// and the URL strip above removes the host before credential scanning. Recognize
	// it on the RAW source and elevate to CapCredentials so it raises VC-002c/d, not
	// a bland VC-002b network note (OPU-19 Part B).
	if m := imdsRe.FindString(source); m != "" {
		allCaps = appendUnique(allCaps, CapCredentials)
		allEvidence = appendStr(allEvidence, "imds:"+m)
	}

	if len(allCaps) > 0 {
		h := Hook{
			Name:     "setup.py:module-level",
			Command:  truncateStr(source, 400),
			Caps:     allCaps,
			Evidence: allEvidence,
			Sinks:    allSinks,
		}
		// Only record URL artifacts from lines with network function calls.
		for _, line := range strings.Split(source, "\n") {
			if hasNetworkCall(line) {
				for _, u := range urlRe.FindAllString(line, -1) {
					h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
				}
			}
		}
		h.Artifacts = dedupeArtifacts(h.Artifacts)
		hooks = append(hooks, h)
	}

	// cmdclass overrides: if the file declares custom install/develop/build_ext
	// commands, each is a distinct hook.
	if cmdclassRe.MatchString(source) {
		for _, cmd := range []string{"install", "develop", "build_ext", "egg_info"} {
			re := regexp.MustCompile(`cmdclass\s*=\s*\{[^}]*\b` + cmd + `\b`)
			if re.MatchString(source) {
				h := Hook{
					Name:    "setup.py:cmdclass." + cmd,
					Command: "cmdclass override: " + cmd,
				}
				// Scan the associated class body if we can find it.
				classRe := regexp.MustCompile(`class\s+\w+\s*\([^)]*` + cmd + `[^)]*\)\s*:`)
				if loc := classRe.FindStringIndex(source); loc != nil {
					body := extractIndentedBlock(source[loc[1]:])
					h.Caps, h.Evidence = scanCaps(body)
					h.Sinks = findSinks(body)
					if m := imdsRe.FindString(body); m != "" {
						h.Caps = appendUnique(h.Caps, CapCredentials)
						h.Evidence = appendStr(h.Evidence, "imds:"+m)
					}
				}
				hooks = append(hooks, h)
			}
		}
	}

	return hooks
}

// knownBuildBackends are PEP 517 build backends that are part of the standard
// Python packaging ecosystem. A package using one of these is not suspicious.
var knownBuildBackends = []string{
	"setuptools.build_meta",
	"flit_core.buildapi",
	"flit.buildapi",
	"poetry.core.masonry.api",
	"poetry.masonry.api",
	"hatchling.build",
	"maturin",
	"scikit_build_core.build",
	"pdm.backend",
	"mesonpy",
	"whey",
	"uv_build", // Astral's uv build backend (uv-managed projects); OPU-29
}

// analyzeBuildBackend checks pyproject.toml for non-standard build backends.
// requires is build-system.requires (see ExtractBuildRequires), used only to
// append a second evidence marker recording whether the declared backend
// could be matched to a pinned entry — the hook itself already fires on the
// backend name alone.
func analyzeBuildBackend(tomlSource string, hasSetupPy bool, requires []string) (Hook, bool) {
	backend := ExtractBuildBackend(tomlSource)

	if backend == "" {
		if hasSetupPy {
			return Hook{
				Name:     "pyproject.toml:build-backend",
				Command:  "no build-backend declared; setup.py runs as legacy build",
				Caps:     []Capability{CapExec},
				Evidence: []string{"legacy-setup.py-fallback"},
			}, true
		}
		return Hook{}, false
	}

	if IsKnownBuildBackend(backend) {
		return Hook{}, false
	}

	evidence := []string{"non-standard-build-backend:" + backend}
	matched, ok, ambiguous := MatchBuildBackendRequires(backend, requires)
	switch {
	case ambiguous:
		evidence = append(evidence, "ambiguous-build-backend-requires")
	case !ok:
		evidence = append(evidence, "missing-requires-entry")
	default:
		evidence = append(evidence, "build-backend-requires:"+matched)
	}

	return Hook{
		Name:     "pyproject.toml:build-backend",
		Command:  "non-standard build backend: " + backend,
		Caps:     []Capability{CapExec},
		Evidence: evidence,
	}, true
}

// IsKnownBuildBackend reports whether backend is one of the standard Python
// packaging ecosystem's PEP 517 build backends.
func IsKnownBuildBackend(backend string) bool {
	// A PEP 517 build-backend is `module` or `module:object`. Match the MODULE
	// part EXACTLY against the known set. The prior HasPrefix match let an
	// attacker name a malicious backend with a known prefix — `hatchling.build_evil`
	// or `hatchling.build.evil_submodule` — and be trusted, suppressing both the
	// non-standard-backend hook and (via the OPU-29 gate) the coverage signal, so
	// the backend executed at build time yet was invisible on every axis (OPU-30).
	// The object suffix on a KNOWN module is not a naming vector: the executing
	// code lives in the known module, so it is stripped before matching.
	module := backend
	if i := strings.IndexByte(module, ':'); i >= 0 {
		module = module[:i]
	}
	module = strings.TrimSpace(module)
	for _, known := range knownBuildBackends {
		if module == known {
			return true
		}
	}
	return false
}

// ExtractBuildRequires reads the build-system.requires array out of
// pyproject.toml without a full TOML parser (D-10). Handles both the
// single-line (`requires = ["a", "b"]`) and multi-line array forms.
func ExtractBuildRequires(toml string) []string {
	inBuildSystem := false
	capturing := false
	var raw strings.Builder
	for _, line := range strings.Split(toml, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[build-system]" {
			inBuildSystem = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inBuildSystem = false
			if capturing {
				break
			}
			continue
		}
		if !inBuildSystem {
			continue
		}
		if capturing {
			raw.WriteByte(' ')
			raw.WriteString(trimmed)
			if strings.Contains(trimmed, "]") {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "requires") {
			if i := strings.IndexByte(trimmed, '='); i >= 0 {
				val := strings.TrimSpace(trimmed[i+1:])
				raw.WriteString(val)
				capturing = true
				if strings.Contains(val, "]") {
					break
				}
			}
		}
	}

	s := raw.String()
	start := strings.IndexByte(s, '[')
	end := strings.LastIndexByte(s, ']')
	if start < 0 || end < 0 || end <= start {
		return nil
	}
	var out []string
	for _, part := range splitTOMLArray(s[start+1 : end]) {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// splitTOMLArray splits a TOML inline-array body on the commas that separate
// its ELEMENTS, ignoring commas inside quoted strings.
//
// A plain strings.Split on "," shreds any element containing one, and a
// compound PEP 440 specifier is exactly that: `requires = ["setuptools>=64,<70"]`
// — the ordinary way a real pyproject.toml bounds its build backend — became
// the two bogus entries "setuptools>=64" and "<70". That is not merely cosmetic.
// `requires = ["evil-backend==64.0.0,!=64.1"]` fragmented into
// "evil-backend==64.0.0", which parses as an exact PIN, so a range was resolved
// to a guessed concrete version and that version was fetched and analyzed —
// precisely what D-01 forbids.
func splitTOMLArray(body string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote byte
	)
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == ',':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, cur.String())
}

// normalizePEP503 applies PEP 503 name normalization (lowercase; runs of -,
// _, . collapse to a single -). Duplicated locally, rather than importing
// internal/purl's equivalent, so this format-agnostic package keeps its
// existing zero-ecosystem-import footprint.
func normalizePEP503(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// MatchBuildBackendRequires finds which entry in requires names the PyPI
// package providing backend. PEP 517 backend strings are import paths, not
// PyPI package names (e.g. "scikit_build_core.build" is provided by the
// "scikit-build-core" package) — the mapping is not mechanical in general, so
// this only matches the PEP-503-normalized LEADING module component of
// backend against each requires entry's PEP-503-normalized name.
//
// Never guesses among multiple candidates (Decision D-01): ambiguous is true
// when more than one requires entry plausibly matches, and resolution then
// declines (ok is false) rather than picking one.
func MatchBuildBackendRequires(backend string, requires []string) (matched string, ok, ambiguous bool) {
	module := backend
	if i := strings.IndexByte(module, '.'); i >= 0 {
		module = module[:i]
	}
	want := normalizePEP503(module)
	if want == "" {
		return "", false, false
	}

	var candidates []string
	for _, r := range requires {
		name, _, _, _ := pep508.Split(r)
		if normalizePEP503(name) == want {
			candidates = append(candidates, r)
		}
	}
	switch len(candidates) {
	case 0:
		return "", false, false
	case 1:
		return candidates[0], true, false
	default:
		return "", false, true
	}
}

// ExtractBuildBackend reads the build-backend value from pyproject.toml without
// a full TOML parser (D-10). Handles the common single-line form.
func ExtractBuildBackend(toml string) string {
	inBuildSystem := false
	for _, line := range strings.Split(toml, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[build-system]" {
			inBuildSystem = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inBuildSystem = false
			continue
		}
		if inBuildSystem && strings.HasPrefix(trimmed, "build-backend") {
			if i := strings.IndexByte(trimmed, '='); i >= 0 {
				val := strings.TrimSpace(trimmed[i+1:])
				val = strings.Trim(val, `"'`)
				return val
			}
		}
	}
	return ""
}

// analyzePthFile checks a .pth file for import lines that execute code.
func analyzePthFile(name, content string) (Hook, bool) {
	var importLines []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "import\t") {
			importLines = append(importLines, trimmed)
		}
	}
	if len(importLines) == 0 {
		return Hook{}, false
	}
	combined := strings.Join(importLines, "\n")
	caps, ev := scanCaps(combined)
	caps = append(caps, CapExec)
	ev = append(ev, "pth-import-line")
	return Hook{
		Name:     "pth:import",
		Command:  name + ": " + truncateStr(combined, 300),
		Caps:     caps,
		Evidence: ev,
		Sinks:    findSinks(combined),
	}, true
}

// pythonMetadataURLRe matches lines where a URL is assigned to a metadata
// variable or appears inside a setup() keyword argument. These are data, not
// code — a homepage URL in __url__ = "https://..." does not mean the hook
// reaches the network.
var pythonMetadataURLRe = regexp.MustCompile(
	`(?i)` +
		`(?:` +
		// __homepage__, __url__, __contact__, url =, download_url =, etc.
		`__\w*(?:url|homepage|contact|repository|tracker|docs)\w*__\s*=` +
		`|` +
		// setup() keyword arguments
		`\b(?:url|download_url|project_urls|author_email|maintainer_email|bugtrack_url|home_page|long_description|description)\s*=` +
		`|` +
		// Dict values in project_urls and similar: "Source": "https://..."
		`["']\w+["']\s*:\s*["']https?://` +
		`|` +
		// Dict entries keyed by known metadata names: 'long_description': '...'
		`["'](?:url|download_url|project_urls|author_email|maintainer_email|bugtrack_url|home_page|long_description|description|license|readme|classifiers)["']\s*:` +
		`|` +
		// Classifier strings
		`pypi\.(?:python\.)?org/pypi\?` +
		`)`,
)

// commentLineRe matches lines that are Python comments (optional leading
// whitespace then #). A URL in a comment is documentation, not network egress.
var commentLineRe = regexp.MustCompile(`^\s*#`)

// metadataStringKeywordRe matches the start of a multi-line string assignment
// to a metadata variable (long_description, license, etc.). URLs inside these
// triple-quoted blocks are README/license content, not network calls.
var metadataStringKeywordRe = regexp.MustCompile(
	`(?i)\b(?:long_description|license|description|readme|__doc__|__long_description__|__license__)\s*=\s*(?:"""|\x60\x60\x60|''')`,
)

// stripPythonMetadataURLs blanks out URLs on lines that are pure metadata
// assignments, inside comments, or inside multi-line metadata strings so they
// don't trigger CapNetwork or become artifacts.
func stripPythonMetadataURLs(source string) string {
	lines := strings.Split(source, "\n")
	inMetadataString := false
	var closer string
	for i, line := range lines {
		// Track multi-line metadata string blocks (long_description = """...""").
		if inMetadataString {
			lines[i] = urlRe.ReplaceAllString(line, "")
			if strings.Contains(line, closer) {
				inMetadataString = false
			}
			continue
		}
		// Detect opening of a multi-line metadata string.
		if metadataStringKeywordRe.MatchString(line) {
			lines[i] = urlRe.ReplaceAllString(line, "")
			// Determine which triple-quote was used and whether it closes on this line.
			for _, q := range []string{`"""`, `'''`} {
				idx := strings.Index(line, q)
				if idx < 0 {
					continue
				}
				rest := line[idx+3:]
				if !strings.Contains(rest, q) {
					inMetadataString = true
					closer = q
				}
			}
			continue
		}
		// Comment lines: URLs here are documentation references.
		if commentLineRe.MatchString(line) {
			lines[i] = urlRe.ReplaceAllString(line, "")
			continue
		}
		// Single-line metadata patterns.
		if pythonMetadataURLRe.MatchString(line) {
			lines[i] = urlRe.ReplaceAllString(line, "")
		}
	}
	return strings.Join(lines, "\n")
}

// extractIndentedBlock returns lines following a class/def header that are
// indented more than the header. Stops at the first unindented line.
func extractIndentedBlock(source string) string {
	lines := strings.SplitAfter(source, "\n")
	var block []string
	for _, line := range lines {
		if len(line) == 0 || line == "\n" {
			block = append(block, line)
			continue
		}
		if line[0] != ' ' && line[0] != '\t' && len(block) > 0 {
			break
		}
		block = append(block, line)
	}
	return strings.Join(block, "")
}

// hasNetworkCall reports whether a line contains a network function call marker.
func hasNetworkCall(line string) bool {
	lower := strings.ToLower(line)
	for _, m := range networkMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

func dedupeArtifacts(in []Artifact) []Artifact {
	seen := map[string]bool{}
	var out []Artifact
	for _, a := range in {
		if !seen[a.Ref] {
			seen[a.Ref] = true
			out = append(out, a)
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// AIAgentConfigFiles are the filesystem paths of AI-coding-agent / editor
// auto-run configuration files that install-time hooks can write as a
// persistence mechanism (OPU-35/OPU-36). They are also scanned DIRECTLY
// when found at the project root (OPU-37) — a separate check from the
// install-hook source scan, covering the case where the file is already
// committed to the repo (either as a pre-existing attack artifact or because
// an earlier install wrote it and the package was subsequently removed while
// the config file survived).
var AIAgentConfigFiles = []string{
	// VS Code (OPU-35)
	".vscode/tasks.json",
	// Claude Code (OPU-35)
	".claude/settings.json",
	".claude/settings.local.json",
	// Claude Code setup hook (Miasma variant — OPU-36)
	".claude/setup.mjs",
	// Cursor AI (OPU-36)
	".cursor/rules",
	".cursorrules",
	// Windsurf (OPU-36)
	".windsurfrules",
	// Google Gemini CLI (OPU-36)
	".gemini/settings.json",
	// GitHub Copilot (OPU-36)
	".github/copilot-instructions.md",
	// MCP (OPU-36)
	"mcp.json",
	// Aider (OPU-36)
	".aider.conf.yml",
}

// AnalyzeAIAgentConfig reads a raw AI-coding-agent / editor configuration
// file and returns a Surface whose hooks represent any auto-run command it
// declares. This is the project-root half of the AI-agent persistence
// detection (OPU-37): it scans files that already exist in the repo rather
// than scanning install-hook source text that WRITES those files (OPU-35/36).
//
// Detection is deliberately conservative: only strings that look like shell
// commands or URLs are extracted and scanned. This is not a JSON/YAML/TOML
// parser — it hands the raw bytes to scanCaps, the same routine that reads
// install-hook source text, so a persistence-marker string or a C2 URL in a
// tasks.json command is caught by the existing machinery without any format-
// specific parsing. This means it cannot distinguish a legitimate watch command
// from a malicious one based on structure alone; it relies on the same
// capability markers (network egress, obfuscation, filesystem writes to
// persistence locations) that distinguish hostile from benign install hooks.
// A project's OWN legitimate tasks.json with a plain `npm run watch` command
// carries no markers and produces no findings. Only one with an explicit
// network call, obfuscation, or persistence write of its own scores.
//
// hookName is used as the pseudo-hook name in the resulting Surface (e.g.
// "tasks.json[folderOpen]"), so findings accurately name the source artifact.
func AnalyzeAIAgentConfig(hookName, fileSource string) Surface {
	clean := stripCodeComments(fileSource)
	caps, ev := scanCaps(clean)
	if len(caps) == 0 {
		return Surface{}
	}
	h := Hook{
		Name:     hookName,
		Command:  truncateStr(fileSource, 400),
		Caps:     caps,
		Evidence: ev,
		Sinks:    findSinks(clean),
	}
	for _, u := range dedupe(urlRe.FindAllString(clean, -1)) {
		h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
	}
	return Surface{Hooks: []Hook{h}}
}
