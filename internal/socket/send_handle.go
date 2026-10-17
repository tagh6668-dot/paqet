package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/unix"

	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
)

type tcpF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type encoder struct {
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP

	opts [5]layers.TCPOption
	ts   [8]byte
	mss  [2]byte
	ws   [1]byte

	buf gopacket.SerializeBuffer
}

type SendHandle struct {
	handle      *pcap.Handle
	writeMu     sync.Mutex
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	time        uint32
	tsCounter   atomic.Uint32
	tcpF        tcpF
	ePool       sync.Pool
	rawIP       bool // true when link type is DLT_RAW (no Ethernet header)
	isCooked    bool
	// AF_PACKET / raw socket for cooked interfaces (ccmni/rmnet, LinkType SLL/SLL2)
	rawFd4 int
	rawFd6 int
	ifName string
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg, 256*1024, 128, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	if err := handle.SetBPFFilter("less 0"); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	sh := &SendHandle{
		handle:  handle,
		srcPort: uint16(cfg.Port),
		rawIP:   cfg.RawIP,
		isCooked: cfg.IsCooked,
		rawFd4:  -1,
		rawFd6:  -1,
		ifName:  cfg.Interface.Name,
		tcpF:    tcpF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:    uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ePool: sync.Pool{
			New: func() any {
				return &encoder{
					eth: layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr},
					mss: [2]byte{0x05, 0xb4},
					ws:  [1]byte{8},
					buf: gopacket.NewSerializeBuffer(),
				}
			},
		},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	// For cooked interfaces (Linux SLL/SLL2 on ccmni/rmnet), pcap cannot send
	// (pcap_sendpacket fails with "Sending packets isn't supported in cooked mode").
	// Open AF_INET raw sockets bound to the interface; Write() will use them.
	if cfg.IsCooked {
		if sh.srcIPv4 != nil {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
			if err == nil {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
				_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, cfg.Interface.Name)
				sh.rawFd4 = fd
			}
		}
		if sh.srcIPv6 != nil {
			fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
			if err == nil {
				// IPV6_HDRINCL on Linux: level IPPROTO_IPV6, opt IPV6_HDRINCL (51)
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, 51, 1)
				_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, cfg.Interface.Name)
				sh.rawFd6 = fd
			}
		}
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(e *encoder, dstIP net.IP) {
	e.ip4 = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      184,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
}

func (h *SendHandle) buildIPv6Header(e *encoder, dstIP net.IP) {
	e.ip6 = layers.IPv6{
		Version:      6,
		TrafficClass: 184,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
}

func (h *SendHandle) buildTCPHeader(e *encoder, dstPort uint16, f conf.TCPF) {
	e.tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := h.tsCounter.Add(1)
	tsVal := h.time + (counter >> 3)
	opts := e.opts[:0]
	if f.SYN {
		binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
		binary.BigEndian.PutUint32(e.ts[4:8], 0)
		opts = append(opts,
			layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: e.mss[:]},
			layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: e.ws[:]},
		)
		e.tcp.Seq = 1 + (counter & 0x7)
		e.tcp.Ack = 0
		if f.ACK {
			e.tcp.Ack = e.tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
		binary.BigEndian.PutUint32(e.ts[4:8], tsEcr)
		opts = append(opts,
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
		)
		seq := h.time + (counter << 7)
		e.tcp.Seq = seq
		e.tcp.Ack = seq - (counter & 0x3FF) + 1400
	}
	e.tcp.Options = opts
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	e := h.ePool.Get().(*encoder)
	defer func() {
		e.buf.Clear()
		h.ePool.Put(e)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	h.buildTCPHeader(e, dstPort, h.getClientTCPF(dstIP, dstPort))

	var ipLayer gopacket.SerializableLayer
	isV4 := dstIP.To4() != nil
	if isV4 {
		h.buildIPv4Header(e, dstIP)
		ipLayer = &e.ip4
		e.tcp.SetNetworkLayerForChecksum(&e.ip4)
		if !h.rawIP {
			e.eth.DstMAC = h.srcIPv4RHWA
			e.eth.EthernetType = layers.EthernetTypeIPv4
		}
	} else {
		h.buildIPv6Header(e, dstIP)
		ipLayer = &e.ip6
		e.tcp.SetNetworkLayerForChecksum(&e.ip6)
		if !h.rawIP {
			e.eth.DstMAC = h.srcIPv6RHWA
			e.eth.EthernetType = layers.EthernetTypeIPv6
		}
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Raw IP / cooked mode (mobile data): skip Ethernet header, inject raw IP packet
	if h.rawIP {
		if err := gopacket.SerializeLayers(e.buf, opts, ipLayer, &e.tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
	} else {
		if err := gopacket.SerializeLayers(e.buf, opts, &e.eth, ipLayer, &e.tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
	}

	rawBytes := e.buf.Bytes()
	// Cooked mode: send via AF_INET raw socket (pcap cannot send on SLL)
	if h.isCooked {
		if isV4 {
			if h.rawFd4 < 0 {
				return fmt.Errorf("no raw socket for IPv4 (cooked mode)")
			}
			var dst unix.SockaddrInet4
			dst.Port = int(dstPort)
			copy(dst.Addr[:], dstIP.To4())
			// raw socket with IP_HDRINCL: kernel sends exactly our IP header + payload
			if err := unix.Sendto(h.rawFd4, rawBytes, 0, &dst); err != nil {
				return err
			}
			return nil
		} else {
			if h.rawFd6 < 0 {
				return fmt.Errorf("no raw socket for IPv6 (cooked mode)")
			}
			var dst unix.SockaddrInet6
			dst.Port = int(dstPort)
			copy(dst.Addr[:], dstIP.To16())
			if err := unix.Sendto(h.rawFd6, rawBytes, 0, &dst); err != nil {
				return err
			}
			return nil
		}
	}

	// Normal Ethernet mode: inject via pcap
	h.writeMu.Lock()
	err := h.handle.WritePacketData(rawBytes)
	h.writeMu.Unlock()
	return err
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) deleteClientTCPF(addr net.Addr) {
	a, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	h.tcpF.mu.Lock()
	delete(h.tcpF.clientTCPF, hash.IPAddr(a.IP, uint16(a.Port)))
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) Close() {
	if h.rawFd4 >= 0 {
		unix.Close(h.rawFd4)
	}
	if h.rawFd6 >= 0 {
		unix.Close(h.rawFd6)
	}
	if h.handle != nil {
		h.handle.Close()
	}
}
