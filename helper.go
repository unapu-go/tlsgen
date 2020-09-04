package tlsgen

import (
	"io"

	"github.com/unapu-go/tlsloader"
)

var ReadFrom = tlsloader.ReadFrom

func WriteTo(s Storage, cb func(w io.Writer) error) (err error) {
	var w io.WriteCloser
	if w, err = s.Writer(); err != nil {
		return
	}
	func() {
		defer func() {
			if err == nil {
				err = w.Close()
			} else {
				w.Close()
			}
		}()
		err = cb(w)
	}()
	return
}
