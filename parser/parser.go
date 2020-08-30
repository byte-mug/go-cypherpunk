package parser

import (
	"io"
	"bytes"
	"bufio"
	
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"strings"
	"regexp"
	"errors"
)

var hdrp = regexp.MustCompile(`([^\:]+)\: (.*)`)

var ErrNoRemail = errors.New("parser: not a remailer message")
var ErrMalformed = errors.New("parser: malformed remailer message")
var ErrBadArmor = errors.New("parser: bad ASCII-ARMOR")

type vreader interface{
	io.Reader
	ReadString(delim byte) (line string, err error)
}

func toVReader(r io.Reader) vreader {
	if v,ok := r.(vreader); ok { return v }
	return bufio.NewReaderSize(r,200)
}
func toBuffer(r vreader) (*bytes.Buffer,error) {
	if b,ok := r.(*bytes.Buffer); ok { return b,nil }
	b := new(bytes.Buffer)
	_,err := b.ReadFrom(r)
	return b,err
}

type RemailerMessage struct{
	Body *bytes.Buffer
	To string
	LatentTime string
}

type Extension func(blk *armor.Block) func(*bytes.Buffer) (*bytes.Buffer,error)

type RemailerParser struct{
	KeyRing openpgp.KeyRing
	
	Exts []Extension
}

func (rp *RemailerParser) decrypt(r vreader) (vreader,error) {
	b,err := armor.Decode(r)
	if err!=nil { return nil, err }
	
	var dec func(*bytes.Buffer) (*bytes.Buffer,error)
	
	if b.Type!="PGP MESSAGE" {
		for _,ext := range rp.Exts {
			dec = ext(b)
			if dec!=nil { break }
		}
		if dec==nil { return nil, ErrBadArmor }
	}
	
	md,err := openpgp.ReadMessage(b.Body,rp.KeyRing,nil,nil)
	if err!=nil { return nil, err }
	buf := new(bytes.Buffer)
	_,err = buf.ReadFrom(md.UnverifiedBody)
	if err==nil && dec!=nil { buf,err = dec(buf) }
	return buf,err
}

func (rp *RemailerParser) parseEntity(r io.Reader) (ren *RemailerMessage,err error) {
	var line string
	v := toVReader(r)
restart:
	for {
		line,err = v.ReadString('\n')
		if err!=nil { return }
		line = strings.TrimSpace(line)
		if line=="" { continue }
		if line!="::" { return nil, ErrNoRemail }
		break
	}
	d := make(map[string]string)
	for {
		line,err = v.ReadString('\n')
		if err!=nil { return }
		line = strings.TrimSpace(line)
		if line=="" { break }
		pair := hdrp.FindStringSubmatch(line)
		if len(pair)==0 { continue }
		d[strings.ToLower(pair[1])] = pair[2]
	}
	if d["encrypted"]=="PGP" {
		v,err = rp.decrypt(v)
		if err!=nil { return }
		goto restart
	}
	
	for {
		line,err = v.ReadString('\n')
		if err!=nil { return }
		line = strings.TrimSpace(line)
		if line=="" { continue }
		if line=="##" { break }
		return nil, ErrMalformed
	}
	
	ren = &RemailerMessage{
		To: d["anon-to"],
		LatentTime: d["latent-time"],
	}
	ren.Body,err = toBuffer(v)
	return
}

func (rp *RemailerParser) ParseMessage(r io.Reader) (*RemailerMessage,error) {
	return rp.parseEntity(r)
}
