//go:build windows

package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

var (
	iphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")
)

const (
	MAXLEN_PHYSADDR = 8
)

type MIB_IPNETROW struct {
	dwIndex       uint32
	dwPhysAddrLen uint32
	bPhysAddr     [MAXLEN_PHYSADDR]byte
	dwAddr        uint32
	dwType        uint32
}

func resolveARP(ip netip.Addr) string {
	// First call to get size
	var dwSize uint32
	ret, _, _ := procGetIpNetTable.Call(
		0,
		uintptr(unsafe.Pointer(&dwSize)),
		0,
	)

	// ERROR_INSUFFICIENT_BUFFER = 122
	if ret != 122 && ret != 0 {
		return ""
	}

	// Allocate buffer
	if dwSize == 0 {
		return ""
	}
	buf := make([]byte, dwSize)

	// Second call to get data
	ret, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dwSize)),
		0,
	)

	if ret != 0 {
		return ""
	}

	// Parse Table
	// Structure:
	// dwNumEntries (4 bytes)
	// Array of MIB_IPNETROW

	count := binary.LittleEndian.Uint32(buf[:4])
	rowSize := uint32(unsafe.Sizeof(MIB_IPNETROW{}))

	// Check against IP
	targetIPUint, err := ipToUint32(ip)
	if err != nil {
		return ""
	}

	start := uint32(4)
	for i := uint32(0); i < count; i++ {
		offset := start + (i * rowSize)
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		// Unsafe cast to struct would be risky with alignment, let's just read bytes manually or use unsafe.P
		// Or simpler: access via pointer arithmetic if struct alignment matches (it should, 4-byte packed mostly).
		row := (*MIB_IPNETROW)(unsafe.Pointer(&buf[offset]))

		if row.dwAddr == targetIPUint {
			// Found
			if row.dwPhysAddrLen > 0 && row.dwPhysAddrLen <= MAXLEN_PHYSADDR {
				macBytes := row.bPhysAddr[:row.dwPhysAddrLen]
				return net.HardwareAddr(macBytes).String()
			}
		}
	}

	return ""
}

func ipToUint32(ip netip.Addr) (uint32, error) {
	if !ip.Is4() {
		return 0, fmt.Errorf("ipv6 not supported for simple table")
	}
	b := ip.As4()
	// Windows dwAddr is generally in Network Byte Order?
	// Wait, MIB_IPNETROW docs say "The IP address is in network byte order."
	// netip.As4() returns bytes in network order (Big Endian sequence).
	// binary.LittleEndian.Uint32 will interpret 192.168.1.1 as 1 + 1<<8 ... which reverses it if strictly LE machine?
	// Actually: "Network Byte Order" usually means Big Endian.
	// But we are reading a uint32.
	// If the system has it as 0x0101A8C0 (192.168.1.1 reversed for LE), then we just alias the bytes.
	// Actually, just casting bytes to uint32 on LE machine gives LE uint.
	// IP "1.2.3.4" (0x01, 0x02, 0x03, 0x04) on LE read as uint32 is 0x04030201.
	// If GetIpNetTable returns Network Byte Order (Big Endian) 0x01020304 into the memory.
	// Then we read it as LE?

	// Let's stick to: The value in memory at `dwAddr` is 4 bytes.
	// We matched `row.dwAddr`.

	// If we read the 4 bytes at row.dwAddr offset?
	// It's cleaner to compare bytes?
	// But `dwAddr` is uint32.

	// Let's just construct the uint32 that matches what we read from the struct.
	// Struct read: row.dwAddr.
	// If we just treat the IP as a uint32 the same way.

	return *(*uint32)(unsafe.Pointer(&b[0])), nil
}
