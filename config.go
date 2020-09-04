package tlsgen

import (
	"os"
	"time"
)

type Config struct {
	CommonName   string        `mapstructure:"common_name"`
	Organization []string      `mapstructure:"organization"`
	Hosts        []string      `mapstructure:"hosts"`
	CertFile     string        `mapstructure:"cert_file"`
	KeyFile      string        `mapstructure:"key_file"`
	FileMode     os.FileMode   `mapstructure:"file_mode"`
	Duration     time.Duration `mapstructure:"duration"`
	Bits         uint16        `mapstructure:"bits"`
	Storage      *PairStorage
}
