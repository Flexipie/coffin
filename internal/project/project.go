// Package project implements the .coffin.toml project file: discovery
// (walking up from the working directory) and parsing, plus the env
// overlay merge semantics (FORMAT.md, "Project file: .coffin.toml").
package project

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Flexipie/coffin/internal/vault"
)

// FileName is the project file's name. Distinct from the vault
// manifest "coffin.toml" (no leading dot).
const FileName = ".coffin.toml"

// manifestName mirrors the vault manifest file name so discovery can
// hint when someone runs a project command inside a vault.
const manifestName = "coffin.toml"

// ErrNotFound is wrapped by Find's error when no .coffin.toml exists
// in the start directory or any parent.
var ErrNotFound = errors.New("no " + FileName + " found")

// File is a parsed, validated .coffin.toml.
type File struct {
	Vault      string // registry name; may be "" (legal with one vault)
	Group      string // normalized env group slug
	DefaultEnv string // normalized single segment; may be ""
	Dir        string // directory containing the file (project root)
	Path       string // full path to the file
}

type fileTOML struct {
	Project struct {
		Vault      string `toml:"vault"`
		Group      string `toml:"group"`
		DefaultEnv string `toml:"default_env"`
	} `toml:"project"`
}

// Find walks up from startDir to the filesystem root and loads the
// first .coffin.toml it meets, git-style. When none exists the error
// wraps ErrNotFound and, if the walk passed through a vault root,
// says so (the two file names are one dot apart).
func Find(startDir string) (*File, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return nil, err
	}
	start := dir
	vaultRoot := ""
	for {
		path := filepath.Join(dir, FileName)
		if _, err := os.Stat(path); err == nil {
			return Load(path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if vaultRoot == "" {
			if _, err := os.Stat(filepath.Join(dir, manifestName)); err == nil {
				vaultRoot = dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	hint := ""
	if vaultRoot != "" {
		hint = fmt.Sprintf("\nnote: %s looks like a coffin vault; %s is a project file that lives in your app repo, not in the vault", vaultRoot, FileName)
	}
	return nil, fmt.Errorf("coffin: %w in %s or any parent - run \"coffin link <group>\" in your project root to connect this repo to a vault env group%s", ErrNotFound, start, hint)
}

// Load parses and validates one .coffin.toml.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := vault.CheckVersion(path, raw); err != nil {
		return nil, err
	}
	var ft fileTOML
	if err := toml.Unmarshal(raw, &ft); err != nil {
		return nil, fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	if strings.TrimSpace(ft.Project.Group) == "" {
		return nil, fmt.Errorf("coffin: %s is missing project.group", path)
	}
	group, err := vault.NormalizeSlug(ft.Project.Group)
	if err != nil {
		return nil, fmt.Errorf("coffin: %s: invalid group: %w", path, err)
	}
	defaultEnv := ""
	if strings.TrimSpace(ft.Project.DefaultEnv) != "" {
		defaultEnv, err = vault.NormalizeSlug(ft.Project.DefaultEnv)
		if err != nil {
			return nil, fmt.Errorf("coffin: %s: invalid default_env: %w", path, err)
		}
		if strings.Contains(defaultEnv, "/") {
			return nil, fmt.Errorf("coffin: %s: default_env %q must be a single segment", path, defaultEnv)
		}
		if defaultEnv == "key" {
			return nil, fmt.Errorf("coffin: %s: default_env %q is reserved for the group key file", path, defaultEnv)
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return &File{
		Vault:      strings.TrimSpace(ft.Project.Vault),
		Group:      group,
		DefaultEnv: defaultEnv,
		Dir:        filepath.Dir(abs),
		Path:       abs,
	}, nil
}
