package modulespec

import (
    "fmt"
    "os"
    "strings"

    "gopkg.in/yaml.v3"
)

type ModuleSpec struct {
    Name string `yaml:"name"`
    Command string `yaml:"command"`
    Args []string `yaml:"args"`
    Env map[string]string `yaml:"env"`
}

func (m ModuleSpec) Environ() []string {
    out := make([]string, 0, len(m.Env))
    for k, v := range m.Env {
        out = append(out, fmt.Sprintf("%s=%s", k, v))
    }
    return out
}

func Load(path string) (ModuleSpec, error) {
    var spec ModuleSpec
    b, err := os.ReadFile(path)
    if err != nil { return spec, err }
    if err := yaml.Unmarshal(b, &spec); err != nil { return spec, err }
    if strings.TrimSpace(spec.Command) == "" {
        return spec, fmt.Errorf("empty command in %s", path)
    }
    return spec, nil
}

