package tlsgen

import (
	"io"
	"os"

	"github.com/unapu-go/safewriter"

	"github.com/unapu-go/tlsloader"
)

type Storage interface {
	tlsloader.Storage
	Writer() (w io.WriteCloser, err error)
}

type PairStorage struct {
	Cert, Key Storage
}

type SafeFileStorage struct {
	tlsloader.FileStorage
	Mode os.FileMode
}

func (this *SafeFileStorage) Writer() (io.WriteCloser, error) {
	return safewriter.Open(this.Path, this.Mode)
}

func NewSafeFileStorage(path string, mode ...os.FileMode) *SafeFileStorage {
	var mode_ os.FileMode
	for _, mode_ = range mode {
	}
	return &SafeFileStorage{*tlsloader.NewFileStorage(path), mode_}
}

func NewSafeFilePairStorage(certPath, keyPath string, mode ...os.FileMode) *PairStorage {
	return &PairStorage{NewSafeFileStorage(certPath, mode...), NewSafeFileStorage(keyPath, mode...)}
}
