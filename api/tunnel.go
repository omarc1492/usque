package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
	}()

	(*packetBufsPtr)[0] = pkt
	_, err := n.dev.Write(*packetBufsPtr, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// CONNECT-IP context ID 0 is encoded as a one-byte QUIC varint. Reserving this
// byte before packets lets connect-ip-go send outbound datagrams in place.
const datagramContextIDHeadroom = 1

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          net.Addr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	UseHTTP2          bool
	// OnConnect is a path to an executable run after every successful tunnel
	// connect. It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnConnect string
	// OnDisconnect is a path to an executable run after every tunnel loss.
	// It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnDisconnect string
	// HookEnv is a set of USQUE_* environment variables layered on top of the
	// parent process env for OnConnect / OnDisconnect invocations. USQUE_EVENT
	// and USQUE_ENDPOINT are set by MaintainTunnel itself.
	HookEnv map[string]string
}

// cloneHookEnv returns a shallow copy of src so concurrent hook invocations
// do not share a map.
func cloneHookEnv(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes first.
// Returns ctx.Err() on cancellation and nil on normal completion.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	if cfg.UseHTTP2 {
		if _, ok := cfg.Endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/2 mode requires a *net.TCPAddr endpoint, got %T", cfg.Endpoint)
		}
	} else {
		if _, ok := cfg.Endpoint.(*net.UDPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/3 mode requires a *net.UDPAddr endpoint, got %T", cfg.Endpoint)
		}
	}

	readerCtx, stopReader := context.WithCancel(context.Background())
	defer stopReader()
	packetBufferPool := NewNetBuffer(cfg.MTU + datagramContextIDHeadroom)
	type devicePacket struct {
		buffer []byte
		size   int
		err    error
	}
	// Match wireguard/netstack's existing 1024-packet channel capacity. Never
	// block the device reader on a full queue: injecting an incoming packet can
	// synchronously produce a reply and wait for another device read.
	packets := make(chan devicePacket, 1024)
	// Device reads cannot be canceled per connection. Keep one reader for the
	// whole device lifetime; its owner closes the device after cancellation.
	go func() {
		for {
			buf := packetBufferPool.Get()
			n, err := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
			if err != nil {
				select {
				case <-readerCtx.Done():
					packetBufferPool.Put(buf)
				case packets <- devicePacket{buf, n, err}:
				}
				return
			}
			if readerCtx.Err() != nil {
				packetBufferPool.Put(buf)
				return
			}
			select {
			case packets <- devicePacket{buf, n, nil}:
			default:
				packetBufferPool.Put(buf) // bounded IP queue; sender can retransmit
			}
		}
	}()
	var pending *devicePacket
	defer func() {
		if pending != nil {
			packetBufferPool.Put(pending.buffer)
		}
	}()

	for ctx.Err() == nil {
		if !cfg.AlwaysReconnect && pending == nil {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")
			select {
			case <-ctx.Done():
				return
			case packet := <-packets:
				pending = &packet
			}
			if pending.err != nil {
				log.Printf("TUN read failed: %v", pending.err)
				return
			}
		}

		log.Printf("Establishing MASQUE connection to %s", cfg.Endpoint)
		cycleCtx, cancelCycle := context.WithCancel(ctx)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			cycleCtx, cfg.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize),
			internal.ConnectURI, cfg.Endpoint, cfg.UseHTTP2,
		)
		cleanup := func() {
			cancelCycle()
			if ipConn != nil {
				_ = ipConn.Close()
			}
			if tr != nil {
				_ = tr.Close()
			}
			if udpConn != nil {
				_ = udpConn.Close()
			}
		}
		if err != nil || rsp.StatusCode != 200 {
			if err != nil {
				log.Printf("Failed to connect tunnel: %v", err)
			} else {
				log.Printf("Tunnel connection failed: %s", rsp.Status)
			}
			cleanup()
			if sleepCtx(ctx, cfg.ReconnectDelay) != nil {
				return
			}
			continue
		}
		log.Println("Connected to MASQUE server")
		if cfg.OnConnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "connect"
			env["USQUE_ENDPOINT"] = cfg.Endpoint.String()
			RunHook(cfg.OnConnect, env)
		}

		incomingError := make(chan error, 1)
		incomingDone := make(chan struct{})
		go func() {
			defer close(incomingDone)
			// Also unblock an outbound send if the incoming stream dies.
			defer ipConn.Close()
			for {
				packet, err := ipConn.ReadPacketZeroCopy(true)
				if err != nil {
					if cfg.UseHTTP2 || errors.As(err, new(*connectip.CloseError)) {
						incomingError <- fmt.Errorf("read from IP connection: %w", err)
						return
					}
					log.Printf("Error reading from IP connection: %v", err)
					continue
				}
				if err := cfg.Device.WritePacket(packet); err != nil {
					incomingError <- fmt.Errorf("write to TUN device: %w", err)
					return
				}
			}
		}()
		stopClose := context.AfterFunc(ctx, func() { _ = ipConn.Close() })
		var connectionError error
		deviceFailed := false
		for connectionError == nil && ctx.Err() == nil {
			if pending == nil {
				select {
				case <-ctx.Done():
				case connectionError = <-incomingError:
				case packet := <-packets:
					pending = &packet
				}
			}
			if pending == nil || connectionError != nil || ctx.Err() != nil {
				continue
			}
			if pending.err != nil {
				connectionError = pending.err
				deviceFailed = true
				break
			}
			// A failed attempted IP send is not replayed: completion is ambiguous
			// and the CONNECT-IP writer mutates TTL / HopLimit in place.
			icmp, writeErr := ipConn.WritePacketBuffer(pending.buffer, datagramContextIDHeadroom, pending.size)
			packetBufferPool.Put(pending.buffer)
			pending = nil
			if writeErr != nil {
				if cfg.UseHTTP2 || errors.As(writeErr, new(*connectip.CloseError)) {
					connectionError = writeErr
				} else {
					log.Printf("Error writing to IP connection: %v", writeErr)
				}
				continue
			}
			if len(icmp) > 0 {
				if err := cfg.Device.WritePacket(icmp); err != nil {
					connectionError = err
					deviceFailed = true
				}
			}
		}
		stopClose()
		cleanup()
		<-incomingDone
		if ctx.Err() != nil || deviceFailed {
			return
		}
		log.Printf("Tunnel connection lost: %v. Reconnecting...", connectionError)
		if cfg.OnDisconnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "disconnect"
			env["USQUE_ENDPOINT"] = cfg.Endpoint.String()
			RunHook(cfg.OnDisconnect, env)
		}
		if sleepCtx(ctx, cfg.ReconnectDelay) != nil {
			return
		}
	}
}
