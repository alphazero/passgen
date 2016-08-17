// Friend!

// Copyright 2016 Joubin Houshyar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// package passgen provides a basic secure password generator. The
// generated passwords are not memorable but are be highly secure.
//
// The generated passwords are of arbitrary length, and conform to
// a basic set of password policies.
package passgen

import (
	"crypto/sha512"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"
)

/// generator ///////////////////////////////////////////////////////////

// password policies
const (
	Printable    = "p"  // any printable character in range (33, 126)
	Alpha        = "a"  // mixed case roman alphabet letters
	Numeric      = "n"  // numeric digits in range (0, 9)
	Alphanumeric = "an" // Alpha and Numeric policies combined.
)

// type Spec encapsulates Generator initialization spec.
type Spec struct {
	Policy       string
	SeedPhrase   string // optional - may be zerovalue/""
	SpecialChars string // optional - may be zerovalue/""
	NoRep        bool   // disallow repeated sequences
}

// Password generator type
type Generator struct {
	spec   Spec
	random io.ReadCloser
	filter Filter
}

// Creates a new Generator with given policy. The provided generator uses
// the OS provided entropy source /dev/random if parameter 'seedPhrase' is
// zerovalue (""). If a seedPhrase is provided, then an OS agnostic entropy
// source is used. The provided seedPhrase must be 8 or more characters in
// length.
//
// Note that OS based generator must be disposed to close the underlying OS
// file. See Generator.Dispose()
func New(spec Spec) (*Generator, error) {

	filter, e := newFilter(spec)
	if e != nil {
		return nil, fmt.Errorf("filter init - %s", e)
	}

	random, e := getRandomSource(spec.SeedPhrase)
	if e != nil {
		return nil, fmt.Errorf("entropy source init - %x", e)
	}

	return &Generator{spec, random, filter}, nil
}

// Frees all associated resources including OS files, if any.
func (p *Generator) Dispose() {
	p.random.Close()
}

// Generates a password of the specified length. An error condition by
// this method is typically unexpected and should be trated as a system
// level fault.
func (p *Generator) Generate(size int) (string, error) {
	var password = make([]byte, size)

	var b [1]byte
	var last uint8 = 127 // DEL can be used as zerovalue
	for i := 0; i < size; {
		_, e := p.random.Read(b[:])
		if e != nil {
			return "", fmt.Errorf("unexpected error reading from random source - %s", e)
		}

		c := uint8(b[0]) % 94
		c += 33
		if p.filter.accept(c) {
			if !p.spec.NoRep || last != c {
				password[i] = byte(c)
				last = c
				i++
			}
		}
	}
	return string(password), nil
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

// use time and provided seedPhrase to source a new prng.
func newRand(seedPhrase string) (*rand.Rand, error) {
	if len(seedPhrase) < 8 {
		return nil, fmt.Errorf("'seedPhrase' must be at least 8 characters")
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

func (filter *Filter) addExtended(specialChars string) {
	//	for _, b := range []byte(specialChars) {
	for _, b := range specialChars {
		c := uint8(b)
		filter[c] = true
	}
}

func (filter *Filter) initPrintable() {
	for i := 33; i < 127; i++ {
		filter[i] = true
	}
}

func newFilter(spec Spec) (filter Filter, err error) {
	switch spec.Policy {
	case Printable:
		filter.initPrintable()
	case Alpha:
		filter.initAlpha()
	case Numeric:
		filter.initNumeric()
	case Alphanumeric:
		filter.initAlphaNumeric()
	default:
		err = fmt.Errorf("unknown policy flag %q", spec.Policy)
	}
	filter.addExtended(spec.SpecialChars)

	return
}
