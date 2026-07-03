// Package tunio abstracts the virtual network interface. The real
// implementation wraps wireguard-go's cross-platform TUN driver
// (/dev/net/tun on Linux, utun on macOS, Wintun on Windows); a channel-based
// in-memory implementation is provided for tests and simulations.
package tunio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

// utunNameRE matches the interface names macOS accepts for TUN devices.
var utunNameRE = regexp.MustCompile(`^utun[0-9]*$`)

// DefaultMTU keeps tunneled packets under the typical 1500-byte path MTU
// after adding UDP, noise, and relay overhead.
const DefaultMTU = 1280

// Device is a virtual NIC carrying raw IP packets.
type Device interface {
	// ReadPacket reads one IP packet into buf and returns its length.
	ReadPacket(buf []byte) (int, error)
	// WritePacket injects one IP packet into the interface.
	WritePacket(pkt []byte) error
	Name() string
	Close() error
}

// tunDevice adapts wireguard-go's batched TUN API to a per-packet API.
type tunDevice struct {
	dev  tun.Device
	name string

	// pending holds packets from a batched read not yet consumed.
	readBufs  [][]byte
	readSizes []int
	pending   [][]byte
}

// offset is the packet start offset required by wireguard-go's TUN
// implementations (room for platform headers such as utun's 4-byte prefix or
// Linux virtio headers).
const offset = 16

// CreateTUN creates the native TUN interface. Pass "" for name to use a
// per-OS default. On macOS the kernel only accepts utun[0-9]* (or plain
// "utun" to auto-number), so other names are coerced to "utun" there.
func CreateTUN(name string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	if runtime.GOOS == "darwin" {
		if !utunNameRE.MatchString(name) {
			name = "utun"
		}
	} else if name == "" {
		name = "vvvlan0"
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("creating TUN interface (are you running with admin/root privileges?): %w", err)
	}
	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	batch := dev.BatchSize()
	d := &tunDevice{
		dev:       dev,
		name:      realName,
		readBufs:  make([][]byte, batch),
		readSizes: make([]int, batch),
	}
	for i := range d.readBufs {
		d.readBufs[i] = make([]byte, offset+65536)
	}
	return d, nil
}

func (d *tunDevice) Name() string { return d.name }

func (d *tunDevice) ReadPacket(buf []byte) (int, error) {
	for len(d.pending) == 0 {
		n, err := d.dev.Read(d.readBufs, d.readSizes, offset)
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return 0, io.EOF
			}
			return 0, err
		}
		for i := 0; i < n; i++ {
			if d.readSizes[i] == 0 {
				continue
			}
			pkt := make([]byte, d.readSizes[i])
			copy(pkt, d.readBufs[i][offset:offset+d.readSizes[i]])
			d.pending = append(d.pending, pkt)
		}
	}
	pkt := d.pending[0]
	d.pending = d.pending[1:]
	n := copy(buf, pkt)
	return n, nil
}

func (d *tunDevice) WritePacket(pkt []byte) error {
	buf := make([]byte, offset+len(pkt))
	copy(buf[offset:], pkt)
	_, err := d.dev.Write([][]byte{buf}, offset)
	return err
}

func (d *tunDevice) Close() error { return d.dev.Close() }

// MemDevice is an in-memory Device for tests: packets written by the engine
// appear on Out, and packets sent to In are read by the engine.
type MemDevice struct {
	In     chan []byte
	Out    chan []byte
	closed chan struct{}
}

// NewMemDevice creates an in-memory device.
func NewMemDevice() *MemDevice {
	return &MemDevice{
		In:     make(chan []byte, 64),
		Out:    make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

func (d *MemDevice) Name() string { return "mem0" }

func (d *MemDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-d.In:
		return copy(buf, pkt), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *MemDevice) WritePacket(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case d.Out <- cp:
		return nil
	case <-d.closed:
		return io.EOF
	default:
		return nil // drop when the test isn't draining
	}
}

func (d *MemDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}
