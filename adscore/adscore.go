package adscore

import (
	"adscore/errors"
	"adscore/parser"
	"adscore/utils"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"
)

const SignatureErrorExpired = 11
const HashSha256 = 1
const SignSha256 = 2
const UseRawHmacKey = false

type payload struct {
	signature   string
	key         string
	ipAddresses []string
	userAgent   string
	signRole    string `default:"customer"`
	expire      int64  `default:"3600"`
}

type Signature struct {
	payload payload
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

func NewSignature(signature string, key string, ipAddresses []string, userAgent string, signRole string, expire int64) *Signature {
	return &Signature{
		payload{
			signature:   signature,
			key:         key,
			ipAddresses: ipAddresses,
			userAgent:   userAgent,
			signRole:    signRole,
			expire:      expire,
		},
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
	return time.Now().Unix()-int64(requestTime) > s.payload.expire
}

func (s Signature) verifyTokens() (map[string]interface{}, error) {
	v4Parser := &parser.V4Parser{}
	data, err := v4Parser.Parse(s.payload.signature)
	if err != nil {
		return nil, err
	}
	if _, ok := data[s.payload.signRole+"Token"]; !ok {
		return nil, errors.NewSignatureError("Invalid sign role", 2)
	}
	signType := data[s.payload.signRole+"SignType"]
	var token []byte
	for _, ipAddress := range s.payload.ipAddresses {
		longIp, err := utils.Ip2long(ipAddress)
		if err != nil {
			return nil, err
		}
		if longIp != 0 {
			ipAddress = utils.Long2ip(longIp)
			token = data[s.payload.signRole+"Token"].([]byte)
		} else {
			//TODO check ipV6
			token = data[s.payload.signRole+"TokenV6"].([]byte)
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
				xValid := s.verifyData(signatureBase, token, "sha256")
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
	return fmt.Sprintf("%d\n%d\n%d\n%s\n%s", result, requestTime, signatureTime, ipAddress, s.payload.userAgent)
}

func (s Signature) hashData(data string, algorithm string) ([]byte, error) {
	if algorithm != "sha256" {
		return nil, errors.SignatureCryptError("Unsupported hash algorithm: " + algorithm)
	}
	bKey := []byte(s.payload.key)
	var err error
	if !UseRawHmacKey {
		bKey, err = utils.FromBase64(s.payload.key)
		if err != nil {
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, bKey)
	mac.Write([]byte(data))
	return mac.Sum(nil), nil
}

func (s Signature) verifyData(data string, signature []byte, algorithm string) bool {
	return false
	//block, _ := pem.Decode([]byte(s.payload.key))
	//pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	//if err != nil {         log.Fatal(err)     }
	//rsa.VerifyPKCS1v15(pub.(), crypto.SHA256, digest[:], decodedSignature)
}
