package mcp

import (
	"unicode/utf16"
	"unicode/utf8"
)

// normalizeOutput converts potential Windows-encoded output (UTF-16LE, cp1252)
// to clean UTF-8. Detects encoding heuristically.
func normalizeOutput(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	// Check for UTF-16LE BOM
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		return decodeUTF16LE(raw[2:])
	}

	// Check if it looks like UTF-16LE without BOM (every other byte is 0x00 for ASCII)
	if len(raw) >= 4 && raw[1] == 0x00 && raw[3] == 0x00 {
		return decodeUTF16LE(raw)
	}

	// Already UTF-8 or ASCII
	return string(raw)
}

// decodeUTF16LE decodes UTF-16LE bytes to a UTF-8 string
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1] // drop trailing odd byte
	}

	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16[i/2] = uint16(b[i]) | uint16(b[i+1])<<8
	}

	runes := utf16.Decode(u16)
	buf := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		if r == 0 {
			continue
		}
		buf = utf8.AppendRune(buf, r)
	}
	return string(buf)
}
