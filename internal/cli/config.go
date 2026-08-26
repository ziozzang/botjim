package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the ~/.botjim/config.json file: default values for the most
// used flags. Precedence is defaults < config < command-line flags — a
// value from the file applies only when the flag was not passed on the
// command line.
type Config struct {
	Port      string   `json:"port"`
	Parallel  int      `json:"parallel"`
	Compress  string   `json:"compress"`
	ZstdLevel int      `json:"zstd_level"`
	Resume    string   `json:"resume"`
	MapOwners string   `json:"map_owners"`
	Exclude   []string `json:"exclude"`
	Include   []string `json:"include"`
	Token     string   `json:"token"`
	Pass      string   `json:"pass"`
	Limit     string   `json:"limit"`
	Retries   int      `json:"retries"`
	LogFile   string   `json:"log_file"`
	Audit     bool     `json:"audit"`
	AuditFile string   `json:"audit_file"`
	Dest      string   `json:"dest"`
	Root      string   `json:"root"`
	NoTUI     bool     `json:"no_tui"`
	SpoolMax  string   `json:"spool_max"`
	SpoolMem  string   `json:"spool_mem"`
	// named endpoints: send/pull take a name instead of HOST[:port]
	Endpoints map[string]Endpoint `json:"endpoints"`
	// per-target autosync policies (sync push/pull)
	Autosync map[string]SyncTarget `json:"autosync"`
}

// Endpoint is one named remote.
type Endpoint struct {
	Addr  string `json:"addr"` // host[:port]
	Token string `json:"token,omitempty"`
	Pass  string `json:"pass,omitempty"`
	Cloak string `json:"cloak,omitempty"`
}

// SyncTarget is the sync policy for one endpoint.
type SyncTarget struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	Dest    string   `json:"dest,omitempty"`   // pull: receive dir
	Delete  bool     `json:"delete,omitempty"` // mirror semantics
}

// ConfigPath is the config file location (~/.botjim/config.json).
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".botjim/config.json"
	}
	return filepath.Join(home, ".botjim", "config.json")
}

// LoadConfig reads the config file; a missing file is an empty config.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// flagPresent reports whether the user passed one of the given flag
// spellings on the command line (--name, --name=v, -s n).
func flagPresent(args []string, names ...string) bool {
	for i, a := range args {
		name := strings.TrimLeft(a, "-")
		if i == 0 && !strings.HasPrefix(a, "-") {
			continue // subcommand word
		}
		for _, n := range names {
			if name == n || strings.HasPrefix(name, n+"=") {
				return true
			}
		}
	}
	return false
}

// apply fills flag values the user did not pass from the config file.
// ResolveEndpoint returns the endpoint stored under name, if any.
func (c *Config) ResolveEndpoint(name string) (Endpoint, bool) {
	if c.Endpoints == nil {
		return Endpoint{}, false
	}
	e, ok := c.Endpoints[name]
	return e, ok
}

func (c *Config) apply(f *flags, args []string) {
	if c.Port != "" && !flagPresent(args, "p", "port") {
		if v, err := parseSizeInt(c.Port); err == nil {
			f.port = int(v)
		}
	}
	if c.Parallel > 0 && !flagPresent(args, "parallel") {
		f.parallel = c.Parallel
	}
	if c.Compress != "" && !flagPresent(args, "compress") {
		f.compressA = c.Compress
	}
	if c.ZstdLevel > 0 && !flagPresent(args, "zstd-level") {
		f.zstdLvl = c.ZstdLevel
	}
	if c.Resume != "" && !flagPresent(args, "resume") {
		f.resume = c.Resume
	}
	if c.MapOwners != "" && !flagPresent(args, "map-owners") {
		f.owners = c.MapOwners
	}
	if len(c.Exclude) > 0 && !flagPresent(args, "exclude") {
		f.exclude = c.Exclude
	}
	if len(c.Include) > 0 && !flagPresent(args, "include") {
		f.include = c.Include
	}
	if c.Token != "" && !flagPresent(args, "token") {
		f.token = c.Token
	}
	if c.Pass != "" && !flagPresent(args, "pass") {
		f.pass = c.Pass
	}
	if c.Limit != "" && !flagPresent(args, "limit") {
		f.limit = c.Limit
	}
	if c.Retries > 0 && !flagPresent(args, "retries") {
		f.retries = c.Retries
	}
	if c.LogFile != "" && !flagPresent(args, "log-file") {
		f.logFile = c.LogFile
	}
	if c.Audit && !flagPresent(args, "audit") {
		f.audit = true
	}
	if c.AuditFile != "" && !flagPresent(args, "audit-file") {
		f.auditFile = c.AuditFile
	}
	if c.Dest != "" && !flagPresent(args, "dest") {
		f.dest = c.Dest
	}
	if c.Root != "" && !flagPresent(args, "root") {
		f.root = c.Root
	}
	if c.NoTUI && !flagPresent(args, "no-tui") {
		f.noTUI = true
	}
}

func parseSizeInt(s string) (int64, error) {
	v, err := parseSize(s)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// applyConfigFromDefaults loads ~/.botjim/config.json (or $BOTJIM_CONFIG)
// and fills any flag the user did not pass.
func applyConfigFromDefaults(f *flags, parsedArgs []string) {
	path := os.Getenv("BOTJIM_CONFIG")
	if path == "" {
		path = ConfigPath()
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: config: %v\n", err)
		return
	}
	// parsedArgs include the subcommand word; flagPresent skips it
	cfg.apply(f, parsedArgs)
}

// cmdConfig implements `botjim config show|path`.
func cmdConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `usage:
  botjim config path           print the config file location
  botjim config show           print the loaded config (JSON)
`)
		return 3
	}
	switch args[0] {
	case "path":
		fmt.Println(ConfigPath())
		return 0
	case "show":
		cfg, err := LoadConfig(ConfigPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(b))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand %q\n", args[0])
		return 3
	}
}
