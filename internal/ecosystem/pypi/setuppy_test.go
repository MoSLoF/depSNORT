package pypi

import "testing"

func TestSetupPyVariableList(t *testing.T) {
	// The Reticulum shape: a conditional assigns the list, then install_requires
	// references it by name.
	raw := []byte(`import setuptools
if pure:
    requirements = []
else:
    requirements = ['cryptography>=3.4.7', 'pyserial>=3.5']
setuptools.setup(
    name="rns",
    install_requires=requirements,
)
`)
	deps := parseSetupPyDeps(raw)
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Constraint
	}
	if got["cryptography"] != ">=3.4.7" {
		t.Errorf("cryptography = %q, want >=3.4.7", got["cryptography"])
	}
	if got["pyserial"] != ">=3.5" {
		t.Errorf("pyserial = %q, want >=3.5", got["pyserial"])
	}
}

func TestSetupPyInlineList(t *testing.T) {
	raw := []byte(`setup(install_requires=["requests>=2.0", "click"])`)
	deps := parseSetupPyDeps(raw)
	if len(deps) != 2 {
		t.Fatalf("deps = %d, want 2", len(deps))
	}
}

func TestSetupPyDynamicDeclinesGracefully(t *testing.T) {
	// install_requires computed from a file read: not statically extractable, so
	// no deps and the file is not claimed as a project.
	raw := []byte(`reqs = open("requirements.txt").read().splitlines()
setup(install_requires=reqs)`)
	if len(parseSetupPyDeps(raw)) != 0 {
		t.Error("a dynamically-built install_requires must yield no static deps")
	}
}

func TestSetupPyNoInstallRequires(t *testing.T) {
	raw := []byte(`setup(name="x", version="1.0")`)
	if setuppyDeclaresDeps2(raw) {
		t.Error("a setup.py with no install_requires is not a resolvable project")
	}
}

func setuppyDeclaresDeps2(raw []byte) bool { return len(parseSetupPyDeps(raw)) > 0 }
