package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/pflag"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestPortfwBindFailureIsSynchronous(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	pm := internal.PortMapping{BindAddress: "127.0.0.1", LocalPort: busy.Addr().(*net.TCPAddr).Port}
	if l, err := listenForwardPort(nil, pm, false); err == nil {
		l.Close()
		t.Fatal("accepted occupied forwarding port")
	}
}
func TestPortfwClosedListenerStopsAcceptLoop(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	done := make(chan error, 1)
	go func() { done <- forwardPort(l, nil, internal.PortMapping{}, false) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing accept error")
		}
	case <-time.After(time.Second):
		t.Fatal("accept loop did not stop")
	}
}
func TestPortfwMissingConfigReturnsFailure(t *testing.T) {
	old := config.ConfigLoaded
	config.ConfigLoaded = false
	defer func() { config.ConfigLoaded = old }()
	if err := portFwCmd.RunE(portFwCmd, nil); err == nil {
		t.Fatal("missing configuration returned success")
	}
}
func TestHTTPProxyDoesNotSendProxyCredentialsToOrigin(t *testing.T) {
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	l, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("100.64.0.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan http.Header, 1)
	origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone(); w.WriteHeader(204) })}
	defer origin.Close()
	go origin.Serve(l)
	req := httptest.NewRequest("GET", "http://"+l.Addr().String()+"/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dummy-test-secret")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("X-Test", "preserved")
	result := httptest.NewRecorder()
	handleHTTPProxy(result, req, stack, nil)
	if result.Code != 204 {
		t.Fatalf("proxy status=%d: %s", result.Code, result.Body.String())
	}
	select {
	case headers := <-seen:
		if headers.Get("Proxy-Authorization") != "" || headers.Get("Proxy-Connection") != "" || headers.Get("X-Test") != "preserved" {
			t.Fatalf("unexpected origin headers: %v", headers)
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive request")
	}
}

func TestPortfwFailedSecondBindClosesFirstListener(t *testing.T) {
	oldContext := portFwCmd.Context()
	portFwCmd.SetContext(context.Background())
	defer portFwCmd.SetContext(oldContext)
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstPort := first.Addr().(*net.TCPAddr).Port
	first.Close()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	oldCfg, oldLoaded := config.AppConfig, config.ConfigLoaded
	config.AppConfig = config.Config{PrivateKey: base64.StdEncoding.EncodeToString(private), EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})), EndpointV4: "127.0.0.1", IPv4: "100.64.0.2", IPv6: "fd00::2"}
	config.ConfigLoaded = true
	defer func() { config.AppConfig = oldCfg; config.ConfigLoaded = oldLoaded }()
	ports := portFwCmd.Flags().Lookup("local-ports")
	oldValue, _ := portFwCmd.Flags().GetStringArray("local-ports")
	oldChanged := ports.Changed
	defer func() { ports.Value.(pflag.SliceValue).Replace(oldValue); ports.Changed = oldChanged }()
	ports.Value.(pflag.SliceValue).Replace([]string{fmt.Sprintf("127.0.0.1:%d:127.0.0.1:8443", firstPort), fmt.Sprintf("127.0.0.1:%d:127.0.0.1:8443", busyPort)})
	err = portFwCmd.RunE(portFwCmd, nil)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint(busyPort)) {
		t.Fatalf("expected second listener bind failure, got %v", err)
	}
	check, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", firstPort))
	if err != nil {
		t.Fatalf("first listener was not rolled back: %v", err)
	}
	check.Close()
	// Cancellation must finish maintenance before releasing the device/listener.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	portFwCmd.SetContext(ctx)
	ports.Value.(pflag.SliceValue).Replace([]string{fmt.Sprintf("127.0.0.1:%d:127.0.0.1:8443", firstPort)})
	if err := portFwCmd.RunE(portFwCmd, nil); err != nil {
		t.Fatalf("canceled startup: %v", err)
	}
	check, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", firstPort))
	if err != nil {
		t.Fatalf("canceled command retained listener: %v", err)
	}
	check.Close()
}
