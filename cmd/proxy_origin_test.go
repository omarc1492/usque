package cmd

import (
	"golang.zx2c4.com/wireguard/tun/netstack"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestHTTPProxyDoesNotSendProxyCredentialsToOrigin(t *testing.T) {
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dev.Close() }()
	l, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("100.64.0.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan http.Header, 1)
	origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone(); w.WriteHeader(204) })}
	defer func() { _ = origin.Close() }()
	go func() { _ = origin.Serve(l) }()
	req := httptest.NewRequest("GET", "http://"+l.Addr().String()+"/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dummy-test-secret")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("X-Test", "preserved")
	result := httptest.NewRecorder()
	client := newTunnelHTTPClient(stack, nil, 0)
	defer client.CloseIdleConnections()
	handleHTTPProxy(result, req, client)
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
