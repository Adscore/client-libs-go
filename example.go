package main

import (
	"adscore/adscore"
	"fmt"
)

func main() {
	signature := ""
	key := "<base 64 encoded sign key>"
	userAgent := ""
	ipAddresses := []string{""}
	signRole := "master"
	s := adscore.NewSignature(signature, key, ipAddresses, userAgent, signRole, 36000000000)
	verify, err := s.Verify()
	if err != nil {
		panic(err)
	}
	fmt.Println(verify)
}
