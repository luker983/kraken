package util

import (
	"encoding/base64"
	"encoding/hex"
)

const (
	ServerPubKey         = "kraKENyGAX30e06miiNHxAzFNHIKxunMdUCZnjPhTCU="
	ServerVirtualAddress = "dead:beef::5a11:b0a7"
	ServerVirtualPort    = 80
	ServerPhysicalPort   = 80
	MTU                  = 32688
)

func UrlKeyToHex(key string) string {
	keyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(keyBytes)
}

func Base64KeyToHex(key string) string {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(keyBytes)
}

func Base64KeyToUrl(key string) string {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(keyBytes)
}
