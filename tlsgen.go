package tlsgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	path_helpers "github.com/moisespsena-go/path-helpers"
	"github.com/moisespsena-go/task"

	"github.com/moisespsena-go/logging"
	"github.com/pkg/errors"

	"github.com/unapu-go/tlsloader"
)

var log = logging.GetOrCreateLogger(path_helpers.GetCalledDir())

type Generator struct {
	cfg    Config
	log    logging.Logger
	renewT *time.Timer
	cert   *tls.Certificate
}

func New(cfg Config, Log ...logging.Logger) *Generator {
	var log_ logging.Logger
	for _, log_ = range Log {
	}
	if log_ == nil {
		log_ = logging.WithPrefix(log, cfg.CertFile)
	}
	if cfg.Bits == 0 {
		cfg.Bits = 4096
	}
	if len(cfg.Organization) == 0 {
		cfg.Organization = []string{"Private Org"}
	}
	if cfg.CommonName == "" {
		cfg.CommonName = "Shared CA"
	}
	if cfg.Duration == 0 {
		cfg.Duration = 365 * 24 * time.Hour
	}
	if cfg.Storage == nil {
		cfg.Storage = NewSafeFilePairStorage(cfg.CertFile, cfg.KeyFile, cfg.FileMode)
	}
	return &Generator{cfg: cfg, log: log_}
}

func (this *Generator) LeftTime() time.Duration {
	return 0
}

func (this *Generator) load() (err error) {
	this.cert, err = tlsloader.Load(this.cfg.CertFile, this.cfg.KeyFile)
	return
}

func (this *Generator) Start(done func()) (stop task.Stoper, err error) {
	if err = this.load(); err != nil {
		if os.IsNotExist(err) {
			this.log.Infof("cert %q does not exists, generate now", this.cfg.CertFile)
			if err = this.Generate(this.cfg.Storage); err != nil {
				return
			}
		} else {
			err = errors.Wrapf(err, "load cert %q and %q failed", this.cfg.CertFile, this.cfg.CertFile)
			return
		}
	} else if err = this.UpdateIfNecessary(); err != nil {
		return
	}

	this.renewT = time.NewTimer(47 * time.Hour)
	go func() {
		defer this.log.Notice("done")
		for this.renewT != nil {
			<-this.renewT.C
			if this.renewT == nil {
				return
			}
			if err := this.UpdateIfNecessary(); err != nil {
				this.log.Error(err)
			}
		}
	}()
	return this, nil
}

func (this *Generator) Stop() {
	this.renewT.Stop()
	this.renewT.Reset(0)
	this.renewT = nil
}

func (this *Generator) IsRunning() bool {
	return this.renewT != nil
}

func (this *Generator) UpdateIfNecessary() (err error) {
	leftTime := this.cert.Leaf.NotAfter.Sub(time.Now())
	if leftTime < 0 {
		this.log.Infof("cert %q expired %s ago. regenerate now.", this.cfg.CertFile, leftTime*-1)
		if err = this.Generate(this.cfg.Storage); err != nil {
			return
		}
	} else if leftTime <= (48 * time.Hour) {
		this.log.Infof("cert %q expires in %s. regenerate now.", this.cfg.CertFile, leftTime)
		if err = this.Generate(this.cfg.Storage); err != nil {
			return
		}
	}
	return

}

func (this *Generator) Generate(storage *PairStorage) (err error) {
	defer func() {
		if err != nil {
			err = errors.Wrapf(err, "generate new cert %q and %q", this.cfg.CertFile, this.cfg.CertFile)
		} else {
			this.log.Infof("new cert expires in %s generated", this.cert.Leaf.NotAfter)
		}
	}()
	// priv, err := rsa.GenerateKey(rand.Reader, *rsaBits)
	var priv *rsa.PrivateKey
	if priv, err = rsa.GenerateKey(rand.Reader, int(this.cfg.Bits)); err != nil {
		return errors.Wrap(err, "generate rsa key")
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: this.cfg.Organization,
			CommonName:   this.cfg.CommonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(this.cfg.Duration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, h := range this.cfg.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv); err != nil {
		return errors.Wrap(err, "create x509 cert")
	}

	err = WriteTo(storage.Cert, func(w io.Writer) error {
		return errors.Wrap(pem.Encode(w, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		}), "create x509 cert file")
	})
	if err != nil {
		return
	}
	err = WriteTo(storage.Key, func(w io.Writer) error {
		return errors.Wrap(pem.Encode(w, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}), "create RSA key file")
	})
	if err != nil {
		return
	}
	if err = this.load(); err != nil {
		return
	}
	return
}
