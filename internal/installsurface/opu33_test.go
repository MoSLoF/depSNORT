package installsurface

import "testing"

// OPU-33 (found during an OPU-32 FP sweep against real-world install
// scripts): decodeRe's hex alternative was a bare `['"]hex['"]\s*\)`, which
// matched the string "hex")" anywhere in a file, including
// .digest('hex') and .toString('hex') — both ENCODE bytes to a hex string
// for display or checksum comparison, not decode one. esbuild's real
// install.js does crypto.createHash("sha256").update(bytes).digest("hex")
// and tripped VC-002e on it (confirmed pre-existing, predates OPU-32).
// These tests lock the fix: the hex alternative now requires the same
// context-bound shape the base64 alternative already used.

func TestHexEncodeDigestNotObfuscation(t *testing.T) {
	negatives := []string{
		// The exact esbuild FP shape.
		`crypto.createHash("sha256").update(bytes).digest("hex")`,
		`crypto.createHash('sha1').update(data).digest('hex')`,
		// .toString('hex') on a Buffer — also an encode, not a decode.
		`checksum.toString("hex")`,
		`Buffer.from(bytes).toString('hex')`,
	}
	for _, text := range negatives {
		if scanHasCap(text, CapObfuscation) {
			t.Errorf("hex ENCODE (digest/toString) must NOT read as obfuscation: %q", text)
		}
	}
}

func TestHexDecodeStillObfuscation(t *testing.T) {
	positives := []string{
		// The real decode idiom the marker exists to catch.
		`Buffer.from(payload, 'hex')`,
		`Buffer.from(encoded, "hex")`,
		// Rust-style naming convention, mirroring the base64 alternatives.
		`from_hex(blob)`,
		`hex::decode(blob).unwrap()`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapObfuscation) {
			t.Errorf("expected CapObfuscation for genuine hex decode: %q", text)
		}
	}
}

// The full esbuild_regression_test.go fixture (esbuildLikeInstallJS) was
// extended under OPU-33 to include the real digest("hex") checksum-verify
// idiom esbuild's actual install.js uses — see TestEsbuildInstallerNotObfuscated
// there for the end-to-end regression this fix closes.
