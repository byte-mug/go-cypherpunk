package pgpz

import (
	"bytes"
	// "github.com/byte-mug/go-cypherpunk/parser"
	"golang.org/x/crypto/openpgp/armor"
	"compress/flate"
)

func Inflate(buf *bytes.Buffer) (*bytes.Buffer,error) {
	dst := new(bytes.Buffer)
	r := flate.NewReader(buf)
	_,err := dst.ReadFrom(r)
	return dst,err
}

func Pgpz(blk *armor.Block) func(*bytes.Buffer) (*bytes.Buffer,error) {
	if blk.Type=="PGPZ MESSAGE" { return Inflate }
	if blk.Type=="COMPRESSD" { return Inflate }
	return nil
}

