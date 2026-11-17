// Package pgprobe checks whether a PostgreSQL server is reachable without a
// database driver or credentials. It resolves the host from a connection URL,
// opens a TCP connection, and sends a PostgreSQL SSLRequest message. A real
// Postgres server answers with a single byte: 'S' (TLS supported) or 'N'
// (TLS not supported). This separates DNS failures, refused connections,
// timeouts and "something that is not Postgres is listening" from
// authentication problems.
package pgprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// sslRequestCode is the magic number from the PostgreSQL frontend/backend
// protocol (1234 << 16 | 5679).
const sslRequestCode = 80877103

// Stage names where a probe can fail.
const (
	StageParse   = "parse"
	StageDNS     = "dns"
	StageConnect = "connect"
	StageProto   = "protocol"
	StageOK      = "ok"
)

// Result describes one probe.
type Result struct {
	Host      string        `json:"host"`
	Port      string        `json:"port"`
	Addresses []string      `json:"addresses,omitempty"`
	Stage     string        `json:"stage"`
	TLS       bool          `json:"tls_supported"`
	Elapsed   time.Duration `json:"elapsed_ns"`
	Err       string        `json:"error,omitempty"`
	Hint      string        `json:"hint,omitempty"`
}

// HostPort extracts host and port from a postgres:// or postgresql:// URL, or
// from a plain host:port string. The port defaults to 5432.
func HostPort(dsn string) (string, string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", "", err
		}
		h, p := u.Hostname(), u.Port()
		if h == "" {
			return "", "", errors.New("URL has no host (unix socket URLs are not supported)")
		}
		if p == "" {
			p = "5432"
		}
		return h, p, nil
	}
	if h, p, err := net.SplitHostPort(dsn); err == nil {
		return h, p, nil
	}
	if dsn == "" {
		return "", "", errors.New("empty address")
	}
	return dsn, "5432", nil
}

// Probe runs the check with the given timeout.
func Probe(ctx context.Context, dsn string, timeout time.Duration) Result {
	start := time.Now()
	h, p, err := HostPort(dsn)
	r := Result{Host: h, Port: p}
	done := func(stage, hint string, err error) Result {
		r.Stage, r.Hint, r.Elapsed = stage, hint, time.Since(start)
		if err != nil {
			r.Err = err.Error()
		}
		return r
	}
	if err != nil {
		return done(StageParse, "check the connection string format", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, h)
	if err != nil {
		return done(StageDNS, "host name does not resolve; inside Docker use the service name on a shared network, not localhost", err)
	}
	r.Addresses = addrs
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h, p))
	if err != nil {
		hint := "nothing accepted the connection; check the port, listen_addresses, firewall and that the server is up"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			hint = "connection timed out; usually a firewall or security group dropping packets"
		}
		return done(StageConnect, hint, err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], sslRequestCode)
	if _, err := c.Write(msg); err != nil {
		return done(StageProto, "connection closed while writing", err)
	}
	b := make([]byte, 1)
	if _, err := c.Read(b); err != nil {
		return done(StageProto, "port is open but did not answer like Postgres (proxy, pooler without TLS handling, or another service)", err)
	}
	switch b[0] {
	case 'S':
		r.TLS = true
		return done(StageOK, "Postgres is answering; if your app still fails, look at credentials and pg_hba.conf", nil)
	case 'N':
		return done(StageOK, "Postgres is answering without TLS; if your app requires sslmode=require it will fail", nil)
	}
	return done(StageProto, "", fmt.Errorf("unexpected reply byte 0x%02x, this is probably not PostgreSQL", b[0]))
}
