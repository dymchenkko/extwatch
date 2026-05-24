package extension

import "testing"

func TestParseDir(t *testing.T) {
	cases := []struct {
		in                               string
		ok                               bool
		pub, name, version, semver, plat string
	}{
		{"eamodio.gitlens-17.12.2", true, "eamodio", "gitlens", "17.12.2", "17.12.2", ""},
		// name itself contains a hyphen
		{"ms-azuretools.vscode-docker-2.0.0", true, "ms-azuretools", "vscode-docker", "2.0.0", "2.0.0", ""},
		// platform suffix on the version
		{"docker.docker-0.18.0-darwin-arm64", true, "docker", "docker", "0.18.0-darwin-arm64", "0.18.0", "darwin-arm64"},
		// non-extension noise the watcher routinely sees
		{"extensions.json", false, "", "", "", "", ""},
		{".obsolete", false, "", "", "", "", ""},
		// VS Code's atomic-install staging dir must be ignored (it's renamed
		// to the real dir, which fires its own event).
		{"eamodio.gitlens-17.12.1.-5f92b72f.vsctmp", false, "", "", "", "", ""},
	}
	for _, c := range cases {
		ext, ok := ParseDir("/root/" + c.in)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if ext.Publisher != c.pub || ext.Name != c.name || ext.Version != c.version || ext.SemVer != c.semver {
			t.Errorf("%s: got pub=%q name=%q ver=%q semver=%q",
				c.in, ext.Publisher, ext.Name, ext.Version, ext.SemVer)
		}
		if got := ext.PlatformSuffix(); got != c.plat {
			t.Errorf("%s: platform=%q want %q", c.in, got, c.plat)
		}
	}
}
