package socket

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"paqet/internal/conf"
)

func newHandle(cfg *conf.Network, sockbuf int, snapLen int, timeout time.Duration) (*pcap.Handle, error) {
	// On Windows, use the GUID field to construct the NPF device name
	// On other platforms, use the interface name directly
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}

	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %v", cfg.Interface.Name, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetBufferSize(sockbuf); err != nil {
		return nil, fmt.Errorf("failed to set pcap buffer size to %d: %v", sockbuf, err)
	}

	if err = inactive.SetSnapLen(snapLen); err != nil {
		return nil, fmt.Errorf("failed to set pcap snap length: %v", err)
	}
	if err = inactive.SetPromisc(false); err != nil {
		return nil, fmt.Errorf("failed to set promiscuous mode: %v", err)
	}
	if err = inactive.SetTimeout(timeout); err != nil {
		return nil, fmt.Errorf("failed to set pcap timeout: %v", err)
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("failed to enable immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		// libpcap on MTK ccmni (ARPHRD 519) returns warning "arptype 519 not supported
		// by libpcap - falling back to cooked socket" but still returns a valid handle
		// with LinkType SLL/SLL2. Treat warning as success.
		msg := err.Error()
		if strings.Contains(msg, "Warning") || strings.Contains(msg, "arptype") || strings.Contains(msg, "falling back") {
			if handle == nil {
				return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
			}
		} else {
			return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
		}
	}

	lt := handle.LinkType()
	cfg.LinkType = lt
	// Classify link type for send/recv handling:
	// - DLT_RAW (12/101) / DLT_IPV4(228)/DLT_IPV6(229): raw IP, no L2 header at all
	// - Linux SLL (113) / SLL2 (276): cooked mode — pcap can capture but cannot send via WritePacketData
	// - MTK ccmni ARPHRD 519 falls back to cooked socket (SLL) — treat same as cooked
	switch lt {
	case 12, layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		cfg.RawIP = true
		cfg.IsCooked = false
	case layers.LinkTypeLinuxSLL, layers.LinkTypeLinuxSLL2:
		cfg.RawIP = true
		cfg.IsCooked = true
	default:
		// Unknown DLT (e.g. 519 ARPHRD_NONE on MTK ccmni that didn't fallback cleanly):
		// assume raw IP cooked mode — safest for mobile data interfaces.
		if int(lt) == 519 || int(lt) == 0 {
			cfg.RawIP = true
			cfg.IsCooked = true
		}
	}

	return handle, nil
}
