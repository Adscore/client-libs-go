package config

type Config struct {
	Signature     string
	Key           string
	IpAddresses   []string
	UserAgent     string
	SignRole      string `default:"customer"`
	Expire        int64  `default:"3600"`
	UseRawHmacKey bool
}
