package supervisor

import (
    "bufio"
    "context"
    "io"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "sync"
    "time"

    "github.com/example/data-kernel/internal/modulespec"
    "github.com/fsnotify/fsnotify"
)

type Supervisor struct {
    dir string
    mu sync.Mutex
    procs map[string]*managedProc
}

type managedProc struct {
    spec modulespec.ModuleSpec
    cmd *exec.Cmd
    stopping bool
    backoff time.Duration
}

func NewSupervisor(dir string) *Supervisor {
    return &Supervisor{dir: dir, procs: map[string]*managedProc{}}
}

func (s *Supervisor) Start(ctx context.Context) error {
    if err := s.scanAndStartAll(ctx); err != nil {
        return err
    }
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return err
    }
    if err := watcher.Add(s.dir); err != nil {
        return err
    }
    go func() {
        defer watcher.Close()
        for {
            select {
            case <-ctx.Done():
                s.stopAll()
                return
            case ev := <-watcher.Events:
                if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
                    _ = s.scanAndStartAll(ctx)
                }
            case err := <-watcher.Errors:
                log.Printf("watch error: %v", err)
            }
        }
    }()
    return nil
}

func (s *Supervisor) scanAndStartAll(ctx context.Context) error {
    entries, err := os.ReadDir(s.dir)
    if err != nil {
        return err
    }
    seen := map[string]bool{}
    for _, e := range entries {
        if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" { continue }
        path := filepath.Join(s.dir, e.Name())
        spec, err := modulespec.Load(path)
        if err != nil { log.Printf("spec load %s: %v", path, err); continue }
        seen[path] = true
        s.ensureRunning(ctx, path, spec)
    }
    // stop removed
    s.mu.Lock()
    for path, mp := range s.procs {
        if !seen[path] {
            mp.stopping = true
            if mp.cmd != nil && mp.cmd.Process != nil {
                _ = mp.cmd.Process.Kill()
            }
            delete(s.procs, path)
        }
    }
    s.mu.Unlock()
    return nil
}

func (s *Supervisor) ensureRunning(ctx context.Context, path string, spec modulespec.ModuleSpec) {
    s.mu.Lock()
    mp, ok := s.procs[path]
    if !ok {
        mp = &managedProc{spec: spec}
        s.procs[path] = mp
    } else {
        mp.spec = spec
    }
    s.mu.Unlock()

    if mp.cmd != nil && mp.cmd.ProcessState == nil { // running
        return
    }
    go s.runLoop(ctx, path, mp)
}

func (s *Supervisor) runLoop(ctx context.Context, path string, mp *managedProc) {
    for {
        if ctx.Err() != nil || mp.stopping { return }
        cmd := exec.CommandContext(ctx, mp.spec.Command, mp.spec.Args...)
        cmd.Env = append(os.Environ(), mp.spec.Environ()...)
        stdout, _ := cmd.StdoutPipe()
        stderr, _ := cmd.StderrPipe()
        if err := cmd.Start(); err != nil {
            log.Printf("start %s: %v", path, err)
            time.Sleep(backoff(&mp.backoff))
            continue
        }
        mp.cmd = cmd
        go stream("stdout", path, stdout)
        go stream("stderr", path, stderr)
        err := cmd.Wait()
        if err != nil {
            log.Printf("proc exit %s: %v", path, err)
        }
        time.Sleep(backoff(&mp.backoff))
    }
}

func stream(kind, path string, r io.ReadCloser) {
    defer r.Close()
    s := bufio.NewScanner(r)
    for s.Scan() {
        log.Printf("%s %s: %s", kind, path, s.Text())
    }
}

func backoff(b *time.Duration) time.Duration {
    if *b == 0 { *b = 500 * time.Millisecond }
    *b *= 2
    if *b > 15*time.Second { *b = 15*time.Second }
    return *b
}

func (s *Supervisor) stopAll() {
    s.mu.Lock()
    defer s.mu.Unlock()
    for _, mp := range s.procs {
        mp.stopping = true
        if mp.cmd != nil && mp.cmd.Process != nil {
            _ = mp.cmd.Process.Kill()
        }
    }
}

