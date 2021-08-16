package adscore

import (
	"adscore/config"
	"adscore/errors"
	"adscore/parser"
	"adscore/utils"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const SignatureErrorExpired = 11
const HashSha256 = 1
const SignSha256 = 2

type Signature struct {
	cfg *config.Config
}

var Results = map[int]map[string]string{
	0: {
		"name":    "Clean",
		"verdict": "ok",
	},
	3: {
		"name":    "Junk",
		"verdict": "junk",
	},
	6: {
		"name":    "Proxy",
		"verdict": "proxy",
	},
	9: {
		"name":    "Bot",
		"verdict": "bot",
	},
}

func NewSignature(cfg *config.Config) *Signature {
	return &Signature{
		cfg: cfg,
	}
}

func (s Signature) Verify() (map[string]interface{}, error) {
	result, err := s.verifyTokens()
	if err != nil {
		return nil, err
	}
	if s.isExpired(result["requestTime"].(uint)) {
		return nil, errors.NewSignatureError("Signature base expired", SignatureErrorExpired)
	}
	return result, nil
}

func (s Signature) isExpired(requestTime uint) bool {
	return time.Now().Unix()-int64(requestTime) > s.cfg.Expire
}

func (s Signature) verifyTokens() (map[string]interface{}, error) {
	v4Parser := &parser.V4Parser{}
	data, err := v4Parser.Parse(s.cfg.Signature)
	if err != nil {
		return nil, err
	}
	if _, ok := data[s.cfg.SignRole+"Token"]; !ok {
		return nil, errors.NewSignatureError("Invalid sign role", 2)
	}
	signType := data[s.cfg.SignRole+"SignType"]
	var token []byte
	for _, ipAddress := range s.cfg.IpAddresses {
		longIp, err := utils.Ip2long(ipAddress)
		if err != nil {
			continue
		}
		if longIp != 0 {
			ipAddress = utils.Long2ip(longIp)
			if _, ok := data[s.cfg.SignRole+"Token"]; !ok {
				continue
			}
			token = data[s.cfg.SignRole+"Token"].([]byte)
		} else {
			ip := net.ParseIP(ipAddress)
			if ip == nil {
				continue
			}
			ipAddress = ip.String()
			if _, ok := data[s.cfg.SignRole+"TokenV6"]; !ok {
				continue
			}
			token = data[s.cfg.SignRole+"TokenV6"].([]byte)
			if token == nil {
				continue
			}
		}
		for result, meta := range Results {
			signatureBase := s.getBase(result, data["requestTime"].(uint), data["signatureTime"].(uint), ipAddress)
			switch signType.(uint) {
			case HashSha256:
				xToken, err := s.hashData(signatureBase, "sha256")
				if err != nil {
					return nil, err
				}
				if bytes.Compare(xToken, token) == 0 {
					return map[string]interface{}{
						"verdict":       meta["verdict"],
						"result":        result,
						"ipAddress":     ipAddress,
						"requestTime":   data["requestTime"],
						"signatureTime": data["signatureTime"],
					}, nil
				}
			case SignSha256:
				xValid, err := s.verifyData(signatureBase, token)
				if err != nil {
					return nil, err
				}
				if xValid {
					return map[string]interface{}{
						"verdict":       meta["verdict"],
						"result":        result,
						"ipAddress":     ipAddress,
						"requestTime":   data["requestTime"],
						"signatureTime": data["signatureTime"],
					}, nil
				}
			default:
				return nil, errors.NewSignatureError("Unrecognized sign type", 3)
			}
		}
	}
	return nil, errors.NewSignatureError("No verdict matched", 10)
}

func (s Signature) getBase(result int, requestTime uint, signatureTime uint, ipAddress string) string {
	return fmt.Sprintf("%d\n%d\n%d\n%s\n%s", result, requestTime, signatureTime, ipAddress, s.cfg.UserAgent)
}

func (s Signature) hashData(data string, algorithm string) ([]byte, error) {
	if algorithm != "sha256" {
		return nil, errors.SignatureCryptError("Unsupported hash algorithm: " + algorithm)
	}
	bKey, err := s.getSignature()
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, bKey)
	mac.Write([]byte(data))
	return mac.Sum(nil), nil
}

func (s Signature) verifyData(data string, signature []byte) (bool, error) {
	bKey, err := s.getSignature()
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(bKey)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	h := sha256.New()
	h.Write([]byte(data))
	switch pub.(type) {
	case *ecdsa.PublicKey:
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			return false, err
		}
		verify := ecdsa.Verify(pub.(*ecdsa.PublicKey), h.Sum(nil), esig.R, esig.S)
		return verify, nil
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, h.Sum(nil), bKey)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, errors.NewSignatureError("signature verify failed", 0)
}

func (s Signature) getSignature() ([]byte, error) {
	bKey := []byte(s.cfg.Key)
	var err error
	if !s.cfg.UseRawHmacKey {
		bKey, err = utils.FromBase64(s.cfg.Key)
		if err != nil {
			return nil, err
		}
	}
	return bKey, err
}
