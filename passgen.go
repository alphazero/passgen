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
	"math/rand"
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
var seedPhrase string

func init() {
	flag.StringVar(&seedPhrase, "input", seedPhrase, "seed phrase for OS agnostic random source")
	flag.IntVar(&size, "s", size, "password-length")
	flag.IntVar(&cnt, "n", cnt, "number of passwords to generate")
	flag.StringVar(&policy, "p", policy, "policy: {p:printable a:alpha n:num an:alphanum")
}

// REVU: good TODO is supporting specified special characters.
func main() {
	flag.Parse()
	filter, e := newFilter(policy)
	if e != nil {
		os.Exit(onError("on init", e))
	}

	random, e := getRandomSource(seedPhrase)
	if e != nil {
		os.Exit(onError("on open", e))
	}
	defer random.Close()

	for n := 0; n < cnt; n++ {
		fmt.Println(generate(size, random, filter))
	}
}

func onError(s string, e error) int {
	fmt.Fprintf(os.Stderr, "err - %s - %s\n", s, e.Error())
	return 1
}

/// generator ///////////////////////////////////////////////////////////

func generate(size int, random io.Reader, filter Filter) string {

	var password = make([]byte, size)

	var b [1]byte
	for i := 0; i < size; {
		_, e := random.Read(b[:])
		if e != nil {
			os.Exit(onError("on read", e))
		}

		c := uint8(b[0]) % 94
		c += 33
		if filter.accept(c) {
			password[i] = byte(c)
			i++
		}
	}
	return string(password)
}

/// random source ///////////////////////////////////////////////////////

// Returns an entorpy source supporting the io.ReadCloser. If seedPhrase
// is true, will use a cryptographic hash based source. Otherwise the OS
// provided /dev/random is used.
func getRandomSource(seedPhrase string) (io.ReadCloser, error) {
	if seedPhrase == "" {
		return os.Open("/dev/random")
	}
	return newEntropySource(seedPhrase)
}

// seedPhrase entropy source type
type entropy struct {
	prng   *rand.Rand
	pool   [64]byte
	offset int
}

func newEntropySource(seedPhrase string) (io.ReadCloser, error) {
	prng, e := newRand(seedPhrase)
	if e != nil {
		return nil, e
	}
	return &entropy{prng: prng, offset: 64}, nil
}

// use time and provided seedPhrase to source a new prng
func newRand(seedPhrase string) (*rand.Rand, error) {
	if len(seedPhrase) < 8 {
		return nil, fmt.Errorf("'input' must be at least 8 characters")
	}
	b := []byte(seedPhrase)

	seed := time.Now().UnixNano()
	shift := []uint{0, 8, 16, 24, 32, 40, 48, 56}
	for i, c := range b {
		c0 := ^int64(c) << shift[i%8]
		seed ^= c0 | (seed >> shift[i%8])
	}
	seed = (seed << 33) | (seed >> 31)

	return rand.New(rand.NewSource(seed)), nil
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
		p.pool = sha512.Sum512([]byte(fmt.Sprintf("%d%v", p.prng.Int63(), time.Now())))
		p.offset = 0
	}

	b[0] = p.pool[p.offset]
	p.offset++
	return 1, nil
}

// nop
func (p *entropy) Close() error { return nil }

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

func newFilter(policy string) (filter Filter, err error) {
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
		err = fmt.Errorf("unknown policy flag %q", policy)
	}

	return
}
