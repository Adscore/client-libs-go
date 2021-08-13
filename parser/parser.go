package parser

import (
	"adscore/errors"
	"adscore/unpacker"
	"adscore/utils"
)

type Parser struct{}

func (p Parser) DecodeSignature(signature string) ([]byte, error) {
	decoded, err := utils.FromBase64(signature)
	if err != nil {
		return nil, errors.NewSignatureError("Not a valid base64 signature payload", 4)
	}
	return decoded, err
}

func (p Parser) UnpackVersionFieldNum(signature []byte) (int, int, error) {
	data, err := unpacker.Unpack("Cversion/CfieldNum", signature)
	return int(data["version"].(uint)), int(data["fieldNum"].(uint)), err
}
