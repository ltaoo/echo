package tun

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
)

const defaultDumpBytes = 256

// shouldDump reports whether the first packet of this connection should be logged.
func (h *tunHandler) shouldDump(processPath string) bool {
	if !h.config.Dump.Enabled {
		return false
	}
	if len(h.config.Dump.Process) == 0 {
		return true
	}
	base := filepath.Base(processPath)
	for _, p := range h.config.Dump.Process {
		if p == base {
			return true
		}
	}
	return false
}

// dumpFirstPacket logs the leading bytes of a connection's first payload together
// with the routing decision, so the transport can be identified by inspection
// instead of by assumption.
func (h *tunHandler) dumpFirstPacket(processPath string, src, dst netip.AddrPort, domain, outbound string, data []byte) {
	limit := h.config.Dump.Bytes
	if limit <= 0 {
		limit = defaultDumpBytes
	}

	shown := data
	if len(shown) > limit {
		shown = shown[:limit]
	}

	h.logger.Info(fmt.Sprintf("[dump] %s %v -> %v domain=%q outbound=%s kind=%s len=%d",
		filepath.Base(processPath), src, dst, domain, outbound, classifyPayload(data), len(data)))

	// hex.Dump yields offset + 16 bytes + ASCII per line, which is what makes a
	// handshake recognizable at a glance: a length prefix followed by a
	// high-entropy block looks nothing like a TLS record header.
	for _, line := range strings.Split(strings.TrimRight(hex.Dump(shown), "\n"), "\n") {
		h.logger.Info("[dump] " + line)
	}
	if len(data) > limit {
		h.logger.Info(fmt.Sprintf("[dump] ... %d more bytes", len(data)-limit))
	}
}

// classifyPayload returns a coarse label for the leading bytes of a payload.
// It is deliberately shallow: enough to route a debugging session, not to parse.
func classifyPayload(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	// TLS record: content type 0x16 (handshake) plus a 0x03xx version.
	if data[0] == 0x16 && len(data) >= 3 && data[1] == 0x03 {
		return "tls"
	}
	// Plaintext HTTP request line.
	if data[0] == 'G' || data[0] == 'P' || data[0] == 'H' || data[0] == 'D' {
		return "http"
	}
	// A 4-byte big-endian length followed by an opaque block. This is the shape a
	// length-prefixed handshake takes, and it is what rules standard TLS out.
	if len(data) >= 5 && data[0] == 0x00 && data[1] == 0x00 {
		return "length-prefixed-opaque"
	}
	return "unknown"
}
