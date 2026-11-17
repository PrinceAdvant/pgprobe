package pgprobe

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHostPort(t *testing.T) {
	cases := map[string][2]string{
		"postgres://u:p@db:6543/app?sslmode=disable": {"db", "6543"},
		"postgresql://u@db.internal/app":             {"db.internal", "5432"},
		"10.0.0.5:5433":                              {"10.0.0.5", "5433"},
		"db":                                         {"db", "5432"},
	}
	for in, want := range cases {
		h, p, err := HostPort(in)
		if err != nil || h != want[0] || p != want[1] {
			t.Errorf("%s: got %s %s %v", in, h, p, err)
		}
	}
}

func fakeServer(t *testing.T, reply byte) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8)
		if _, err := c.Read(buf); err != nil || binary.BigEndian.Uint32(buf[4:]) != sslRequestCode {
			return
		}
		c.Write([]byte{reply})
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestProbe(t *testing.T) {
	r := Probe(context.Background(), fakeServer(t, 'S'), 2*time.Second)
	if r.Stage != StageOK || !r.TLS {
		t.Fatalf("want ok+tls, got %+v", r)
	}
	r = Probe(context.Background(), fakeServer(t, 'N'), 2*time.Second)
	if r.Stage != StageOK || r.TLS {
		t.Fatalf("want ok no tls, got %+v", r)
	}
	r = Probe(context.Background(), fakeServer(t, 'X'), 2*time.Second)
	if r.Stage != StageProto {
		t.Fatalf("want protocol stage, got %+v", r)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	r = Probe(context.Background(), addr, 2*time.Second)
	if r.Stage != StageConnect {
		t.Fatalf("want connect stage, got %+v", r)
	}
}
