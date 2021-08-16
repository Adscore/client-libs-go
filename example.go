package main

import (
	"adscore/adscore"
	"adscore/config"
	"fmt"
)

func main() {
	signature := ""
	key := "<base 64 encoded sign key>"
	userAgent := ""
	ipAddresses := []string{""}
	signRole := "master"
	cfg := &config.Config{
		Signature:     signature,
		Key:           key,
		IpAddresses:   ipAddresses,
		UseRawHmacKey: false,
		UserAgent:     userAgent,
		Expire:        21660,
		SignRole:      signRole,
	}
	s := adscore.NewSignature(cfg)
	verify, err := s.Verify()
	if err != nil {
		panic(err)
	}
	fmt.Println(verify)
}
