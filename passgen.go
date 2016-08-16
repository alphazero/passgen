// friend!
// Copyright 2016 Joubin Houshyar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha512"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

/// tool ////////////////////////////////////////////////////////////////

const (
	printable    = "p"
	alpha        = "a"
	numeric      = "n"
	alphanumeric = "an"
)

var policy = printable
var size = 64
var cnt = 1
var portable bool

func init() {
	flag.BoolVar(&portable, "portable", portable, "use OS agnostic random source")
	flag.IntVar(&size, "s", size, "password-length")
	flag.IntVar(&cnt, "n", cnt, "number of passwords to generate")
	flag.StringVar(&policy, "p", policy, "policy: {p:printable a:alpha n:num an:alphanum")
}

func main() {
	flag.Parse()
	filter := newFilter(policy)

	var random io.ReadCloser
	random, e := getRandomSource(portable)
	if e != nil {
		os.Exit(onError("on open", e))
	}
	defer random.Close()

	for n := 0; n < cnt; n++ {
		generate(random, filter)
	}
}

/// generator ///////////////////////////////////////////////////////////

func generate(random io.Reader, filter Filter) {

	var b [1]byte
	for i := 0; i < size; {
		_, e := random.Read(b[:])
		if e != nil {
			os.Exit(onError("on read", e))
		}

		c := uint8(b[0]) % 94
		c += 33
		if filter.accept(c) {
			fmt.Printf("%c", c)
			i++
		}
	}
	fmt.Println()
}

/// random source ///////////////////////////////////////////////////////

func getRandomSource(portable bool) (io.ReadCloser, error) {
	if portable {
		return newCryptoHashSource()
	}
	return os.Open("/dev/random")
}

type entropy struct {
	pool   [64]byte
	offset int
}

// constrained support for io.Read interface. internal useage of  this
// function is always expected to provide buffer b of len 1 so functionally
// it is more accurately an io.ByteReader but for sake of keeping things
// simple it is more convenient to support the Reader api instead.
func (p *entropy) Read(b []byte) (int, error) {
	if len(b) > 1 {
		return 0, fmt.Errorf("BUG - entropy.Read usage error")
	}
	if p.offset == len(p.pool) {
		p.pool = sha512.Sum512([]byte(fmt.Sprintf("%d", time.Now())))
		p.offset = 0
	}

	b[0] = p.pool[p.offset]
	p.offset++
	return 1, nil
}

// nop
func (p *entropy) Close() error { return nil }

func newCryptoHashSource() (io.ReadCloser, error) {
	return &entropy{offset: 64}, nil
}

/// filter //////////////////////////////////////////////////////////////

type Filter [256]bool

func (filter Filter) accept(c uint8) bool {
	return filter[c]
}
func (filter *Filter) initAlpha() {
	for i := 65; i < 91; i++ {
		filter[i] = true
		filter[i+32] = true
	}
}

func (filter *Filter) initNumeric() {
	for i := 48; i < 58; i++ {
		filter[i] = true
	}
}

func (filter *Filter) initAlphaNumeric() {
	filter.initAlpha()
	filter.initNumeric()
}

func (filter *Filter) initPrintable() {
	for i := 33; i < 127; i++ {
		filter[i] = true
	}
}

func newFilter(policy string) (filter Filter) {
	switch policy {
	case printable:
		filter.initPrintable()
	case alpha:
		filter.initAlpha()
	case numeric:
		filter.initNumeric()
	case alphanumeric:
		filter.initAlphaNumeric()
	default:
		os.Exit(onError(policy, fmt.Errorf("unknown policy flag")))
	}

	return
}

func onError(s string, e error) int {
	fmt.Fprintf(os.Stderr, "err - %s - %s\n", s, e.Error())
	return 1
}
