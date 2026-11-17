package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for local test event")
		var v T
		return v
	}
}

func localH2(t *testing.T, handler http.Handler, useHTTP2 bool) (*httptest.Server, *tls.Config, *net.TCPAddr, <-chan struct{}) {
	t.Helper()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		t.Setenv(name, "")
	}
	t.Setenv("NO_PROXY", "*")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 20)
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = useHTTP2
	if useHTTP2 {
		if err := http2.ConfigureServer(s.Config, &http2.Server{MaxUploadBufferPerStream: 65535, MaxUploadBufferPerConnection: 65535}); err != nil {
			t.Fatal(err)
		}
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	s.StartTLS()
	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })
	cfg, err := PrepareTlsConfig(key, &key.PublicKey, [][]byte{der}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	return s, cfg, s.Listener.Addr().(*net.TCPAddr), closed
}

type fakeDevice struct {
	input      chan []byte
	done       chan struct{}
	once       sync.Once
	readers    atomic.Int32
	maxReaders atomic.Int32
	write      func([]byte) error
}

func newDevice() *fakeDevice { return &fakeDevice{input: make(chan []byte), done: make(chan struct{})} }
func (d *fakeDevice) close() { d.once.Do(func() { close(d.done) }) }
func (d *fakeDevice) ReadPacket(buf []byte) (int, error) {
	current := d.readers.Add(1)
	defer d.readers.Add(-1)
	for {
		old := d.maxReaders.Load()
		if old >= current || d.maxReaders.CompareAndSwap(old, current) {
			break
		}
	}
	select {
	case <-d.done:
		return 0, io.EOF
	case packet := <-d.input:
		return copy(buf, packet), nil
	}
}
func (d *fakeDevice) WritePacket(packet []byte) error {
	if d.write != nil {
		return d.write(packet)
	}
	return nil
}
func packet(id byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	b[3] = 20
	b[4] = id
	b[8] = 64
	b[9] = 17
	return b
}
func readCapsule(r io.Reader) ([]byte, error) {
	v := quicvarint.NewReader(r)
	kind, err := quicvarint.Read(v)
	if err != nil {
		return nil, err
	}
	if kind != 0 {
		return nil, fmt.Errorf("unexpected capsule %d", kind)
	}
	n, err := quicvarint.Read(v)
	if err != nil {
		return nil, err
	}
	b := make([]byte, n)
	_, err = io.ReadFull(v, b)
	return b, err
}
func writeCapsule(w io.Writer, b []byte) {
	frame := quicvarint.Append(nil, 0)
	frame = quicvarint.Append(frame, uint64(len(b)))
	frame = append(frame, b...)
	_, _ = w.Write(frame)
}

type session struct {
	close   chan struct{}
	packets chan []byte
}

func sessionHandler(opened chan<- session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		s := session{make(chan struct{}), make(chan []byte, 10)}
		opened <- s
		go func() {
			for {
				b, err := readCapsule(r.Body)
				if err != nil {
					return
				}
				s.packets <- b
			}
		}()
		select {
		case <-s.close:
		case <-r.Context().Done():
		}
	})
}
func startMaintenance(t *testing.T, cfg MaintainTunnelConfig) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); MaintainTunnel(ctx, cfg) }()
	t.Cleanup(cancel)
	return cancel, done
}
func TestIdleReconnectHasOneDeviceReader(t *testing.T) {
	opened := make(chan session, 10)
	_, tlsCfg, endpoint, _ := localH2(t, sessionHandler(opened), true)
	d := newDevice()
	defer d.close()
	cancel, done := startMaintenance(t, MaintainTunnelConfig{TLSConfig: tlsCfg, Endpoint: endpoint, Device: d, MTU: 1280, UseHTTP2: true, AlwaysReconnect: true, ReconnectDelay: time.Millisecond})
	s := receive(t, opened)
	for i := byte(1); i <= 4; i++ {
		close(s.close)
		s = receive(t, opened)
		select {
		case d.input <- packet(i):
		case <-time.After(4 * time.Second):
			t.Fatal("reader stuck")
		}
		got := receive(t, s.packets)
		if got[4] != i || got[8] != 63 {
			t.Fatalf("lost/corrupted packet after reconnect: %v", got)
		}
	}
	cancel()
	receive(t, done)
	if got := d.maxReaders.Load(); got != 1 {
		t.Fatalf("concurrent TUN readers=%d", got)
	}
}
func TestIdleWakeupPacketSurvivesDialFailure(t *testing.T) {
	opened := make(chan session, 2)
	var attempts atomic.Int32
	next := sessionHandler(opened)
	_, tlsCfg, endpoint, _ := localH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		next.ServeHTTP(w, r)
	}), true)
	d := newDevice()
	defer d.close()
	cancel, done := startMaintenance(t, MaintainTunnelConfig{TLSConfig: tlsCfg, Endpoint: endpoint, Device: d, MTU: 1280, UseHTTP2: true, ReconnectDelay: time.Millisecond})
	select {
	case d.input <- packet(9):
	case <-time.After(4 * time.Second):
		t.Fatal("reader stuck")
	}
	s := receive(t, opened)
	got := receive(t, s.packets)
	if got[4] != 9 || got[8] != 63 {
		t.Fatalf("wakeup packet not preserved: %v", got)
	}
	cancel()
	receive(t, done)
}
func TestCancellationDrainsSynchronousDeviceReplies(t *testing.T) {
	// Model netstack.InjectInbound: a device write emits replies synchronously
	// and waits for the TUN reader. Exceed the handoff queue during shutdown.
	entered := make(chan struct{})
	release := make(chan struct{})
	written := make(chan struct{})
	d := newDevice()
	defer d.close()
	d.write = func([]byte) error {
		close(entered)
		<-release
		for i := 0; i < 2048; i++ {
			select {
			case d.input <- packet(byte(i)):
			case <-d.done:
				return io.EOF
			}
		}
		close(written)
		return nil
	}
	_, tlsCfg, endpoint, _ := localH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		writeCapsule(w, packet(7))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), true)
	cancel, done := startMaintenance(t, MaintainTunnelConfig{TLSConfig: tlsCfg, Endpoint: endpoint, Device: d, MTU: 1280, UseHTTP2: true, AlwaysReconnect: true})
	receive(t, entered)
	cancel()
	close(release)
	receive(t, written)
	receive(t, done)
}

func TestCancellationClosesStalledHTTP2Send(t *testing.T) {
	opened := make(chan struct{}, 1)
	_, tlsCfg, endpoint, _ := localH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		opened <- struct{}{}
		<-r.Context().Done()
	}), true)
	d := newDevice()
	defer d.close()
	cancel, done := startMaintenance(t, MaintainTunnelConfig{TLSConfig: tlsCfg, Endpoint: endpoint, Device: d, MTU: 1280, UseHTTP2: true, AlwaysReconnect: true})
	receive(t, opened)
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < 4096; i++ {
			b := make([]byte, 1280)
			copy(b, packet(byte(i)))
			b[2] = 5
			b[3] = 0
			select {
			case d.input <- b:
			case <-d.done:
				return
			}
		}
	}()
	receive(t, sent)
	deadline := time.Now().Add(3 * time.Second)
	stalled := false
	for time.Now().Before(deadline) {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		// The pinned x/net implementation exposes this frame while blocked on
		// peer flow control; revisit this probe when updating that dependency.
		if strings.Contains(string(stack[:n]), "awaitFlowControl") {
			stalled = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !stalled {
		t.Fatal("did not establish a flow-control-stalled request sender")
	}
	cancel()
	receive(t, done)
}

func TestDeviceReadFailureEndsMaintenance(t *testing.T) {
	device := newDevice()
	device.close()
	_, done := startMaintenance(t, MaintainTunnelConfig{Device: device, MTU: 1280, UseHTTP2: true, Endpoint: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, ReconnectDelay: time.Second})
	receive(t, done)
}
