package utils

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

func Substr(input string, start int, length int) string {
	asRunes := []rune(input)

	if start >= len(asRunes) {
		return ""
	}

	if start+length > len(asRunes) {
		length = len(asRunes) - start
	}

	return string(asRunes[start : start+length])
}

func CharAt(str string, idx int) string {
	if idx < 0 || idx >= len(str) {
		return "0"
	}
	return string(str[idx])
}

func Ip2long(ipAddr string) (uint32, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return 0, errors.New("wrong ipAddr format")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

func Long2ip(ipLong uint32) string {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, ipLong)
	ip := net.IP(ipByte)
	return ip.String()
}
func FromBase64(signature string) ([]byte, error) {
	signature = strings.ReplaceAll(signature, "-", "+")
	signature = strings.ReplaceAll(signature, "_", "/")
	decoded, err := base64.RawStdEncoding.DecodeString(signature)
	return decoded, err
}
