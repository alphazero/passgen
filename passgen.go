// friend!
// Copyright 2016 Joubin Houshyar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	printable    = "p"
	alpha        = "a"
	numeric      = "n"
	alphanumeric = "an"
)

var policy = printable
var size = 64
var cnt = 1

func init() {
	flag.IntVar(&size, "s", size, "password-length")
	flag.IntVar(&cnt, "n", cnt, "number of passwords to generate")
	flag.StringVar(&policy, "p", policy, "policy: {p:printable a:alpha n:num an:alphanum")
}

func main() {
	flag.Parse()
	filter := newFilter(policy)

	for n := 0; n < cnt; n++ {
		generate(filter)
	}
}

func generate(filter Filter) {
	f, e := os.Open("/dev/random")
	if e != nil {
		os.Exit(onError("on open", e))
	}

	var b [1]byte
	for i := 0; i < size; {
		_, e = f.Read(b[:])
		if e != nil {
			os.Exit(onError("on read", e))
		}

		c := uint8(b[0]) % 94
		c += 33
		if !filter.accept(c) {
			continue
		}
		fmt.Printf("%c", c)
		i++
	}
	fmt.Println()
}

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
