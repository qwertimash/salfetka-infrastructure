package nodewire

import "regexp"

// Empty is the original VLESS profile, preserving old signed canonical bodies.
const BackendHysteria2 = "hysteria2"
const BackendOLCRTC = "olcrtc"

func ValidBackend(s string) bool { return s == "" || s == BackendHysteria2 || s == BackendOLCRTC }

var keyHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidOLCKey(s string) bool { return keyHex.MatchString(s) }
