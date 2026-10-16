package socket

import (
	"fmt"
	"runtime"
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
		return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
	}

	// Detect Raw IP interfaces (mobile data: rmnet, ccmni, etc.).
	// DLT_RAW is 12 in classic BSD numbering and 101 in the modern
	// tcpdump LINKTYPE registry; DLT_IPV4/DLT_IPV6 (228/229) are
	// v4-only/v6-only raw captures. All carry raw IP with no Ethernet header.
	lt := handle.LinkType()
	switch lt {
	case 12, layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		cfg.RawIP = true
	}

	return handle, nil
}
