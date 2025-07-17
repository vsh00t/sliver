package evasion

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Stage 1.2: Enhanced Evasion - String obfuscation utilities

// SimpleDecrypt performs basic XOR decryption to obfuscate static strings
func SimpleDecrypt(encrypted string, key byte) string {
	decrypted := make([]byte, len(encrypted))
	for i, b := range []byte(encrypted) {
		decrypted[i] = b ^ key
	}
	return string(decrypted)
}

// GetObfuscatedDLLNames returns obfuscated system DLL names
func GetObfuscatedDLLNames() map[string]string {
	// XOR key: 0x42
	return map[string]string{
		"ntdll":      SimpleDecrypt("\x2c\x36\x26\x2e\x2e", 0x42),                     // "ntdll"
		"kernel32":   SimpleDecrypt("\x29\x27\x30\x2c\x27\x2e\x11\x10", 0x42),         // "kernel32"
		"kernelbase": SimpleDecrypt("\x29\x27\x30\x2c\x27\x2e\x24\x21\x31\x27", 0x42), // "kernelbase"
	}
}

// BuildDLLPath constructs the full DLL path with obfuscated components
func BuildDLLPath(dllName string) string {
	// Obfuscated path components - XOR key: 0x33
	sysPath := SimpleDecrypt("\x66\x7c\x66\x56\x76\x7e\x63\x7f\x5c\x50\x50", 0x33) // "C:\Windows\"
	sys32 := SimpleDecrypt("\x42\x56\x42\x43\x76\x7e\x50\x10", 0x33)               // "System32\"
	extension := SimpleDecrypt("\x7f\x64\x61", 0x33)                               // ".dll"

	return sysPath + sys32 + dllName + extension
}

// InitializeStringObfuscation sets up string obfuscation capabilities
func InitializeStringObfuscation() map[string]interface{} {
	config := make(map[string]interface{})
	config["strings_obfuscated"] = true
	config["dlls_obfuscated"] = GetObfuscatedDLLNames()
	return config
}
