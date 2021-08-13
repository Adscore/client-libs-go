package parser

type FieldType struct {
	Name string
	Type string
}
var FieldIds = map[uint]FieldType {
	0x00: {
		Name: "requestTime",
		Type: "ulong",
	},
	0x01: {
		Name: "signatureTime",
		Type: "ulong",
	},
	0x40: {
		Name: "",
		Type: "ushort",
	},
	0x80: {
		Name: "masterSignType",
		Type: "uchar",
	},
	0x81: {
		Name: "customerSignType",
		Type: "uchar",
	},
	0xC0: {
		Name: "masterToken",
		Type: "string",
	},
	0xC1: {
		Name: "customerToken",
		Type: "string",
	},
	0xC2: {
		Name: "masterTokenV6",
		Type: "string",
	},
	0xC3: {
		Name: "customerTokenV6",
		Type: "string",
	},
}