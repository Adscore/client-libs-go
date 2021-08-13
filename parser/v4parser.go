package parser

import (
	"adscore/errors"
	"adscore/unpacker"
	"fmt"
)

type V4Parser struct {
	Parser
}

func (p *V4Parser) Parse(strSignature string) (map[string]interface{}, error) {
	data := map[string]interface{}{}
	signature, err := p.Parser.DecodeSignature(strSignature)
	if err != nil {
		return nil, err
	}
	version, fieldNum, err := p.Parser.UnpackVersionFieldNum(signature)
	if err != nil {
		return nil, err
	}
	if version != 4 {
		return nil, errors.NewSignatureError("Signature version not supported", 5)
	}

	signature = signature[2:]
	for i := 0; i < fieldNum; i++ {
		unpacked, err := unpacker.Unpack("CfieldId", signature)
		if err != nil {
			return nil, err
		}
		fieldId := unpacked["fieldId"]
		if fieldId == nil {
			return nil, errors.NewSignatureError("Premature end of signature", 6)
		}
		var fieldTypeDef FieldType
		if val, ok := FieldIds[fieldId.(uint)]; ok {
			fieldTypeDef = val
		} else {
			newFieldType := FieldIds[fieldId.(uint)&0xC0].Type
			fieldTypeDef = FieldType{
				Name: fmt.Sprintf("%s%02x", newFieldType, i),
				Type: newFieldType,
			}
		}
		switch fieldTypeDef.Type {
		case "uchar":
			unpacked, err = unpacker.Unpack("Cx/Cv", signature)
			if err != nil {
				return nil, err
			}
			data[fieldTypeDef.Name] = unpacked["v"]
			signature = signature[2:]
		case "ushort":
			unpacked, err = unpacker.Unpack("Cx/nv", signature)
			if err != nil {
				return nil, err
			}
			data[fieldTypeDef.Name] = unpacked["v"]
			signature = signature[3:]
		case "ulong":
			unpacked, err = unpacker.Unpack("Cx/Nv", signature)
			if err != nil {
				return nil, err
			}
			data[fieldTypeDef.Name] = unpacked["v"]
			signature = signature[5:]
		case "string":
			unpacked, err = unpacker.Unpack("Cx/nl", signature)
			if err != nil {
				return nil, err
			}
			length := unpacked["l"].(uint)
			if length&0x8000 > 0 {
				/* For future use */
				length = length & 0xFF
			}
			name := signature[3 : length+3]
			if len(name) != int(length) {
				return nil, errors.NewSignatureError("Premature end of signature", 0)
			}
			data[fieldTypeDef.Name] = name
			signature = signature[3+int(length):]
		default:
			return nil, errors.NewSignatureError("Unsupported variable type", 0)
		}
	}
	return data, nil
}
