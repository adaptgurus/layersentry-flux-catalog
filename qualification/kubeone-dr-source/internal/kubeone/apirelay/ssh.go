package apirelay

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"
)

type sshTransport struct{ key, pins string }

func (t *sshTransport) args() []string {
	return []string{"-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + t.pins, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
		"-o", "GSSAPIAuthentication=no", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no", "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=5",
		"-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-i", t.key}
}

func (t *sshTransport) Probe(ctx context.Context, peer, destination string) error {
	host, port, err := net.SplitHostPort(destination)
	if err != nil || net.ParseIP(host).To4() == nil || port != "6443" {
		return errors.New("invalid fixed relay destination")
	}
	// All interpolated values originate from the compiled site profile, never
	// client bytes. The native remote command performs only a bounded TCP open.
	probe := "/usr/bin/timeout 4 /bin/bash -c 'exec 3<>/dev/tcp/" + host + "/6443'"
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", append(t.args(), "ubuntu@"+peer, probe)...)
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		return errors.New("relay peer API path unavailable")
	}
	return nil
}

func (t *sshTransport) Open(ctx context.Context, peer, destination string) (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", append(t.args(), "-W", destination, "ubuntu@"+peer)...)
	cmd.WaitDelay = time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, errors.New("relay pipe unavailable")
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		out.Close()
		cancel()
		return nil, errors.New("relay pipe unavailable")
	}
	if cmd.Start() != nil {
		in.Close()
		out.Close()
		cancel()
		return nil, errors.New("relay SSH start failed")
	}
	p := &sshPipe{in: in, out: out, cancel: cancel, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	return p, nil
}

type sshPipe struct {
	in     io.WriteCloser
	out    io.ReadCloser
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (p *sshPipe) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *sshPipe) Write(b []byte) (int, error) { return p.in.Write(b) }
func (p *sshPipe) Close() error {
	p.once.Do(func() { p.cancel(); p.in.Close(); p.out.Close(); <-p.done })
	return nil
}
