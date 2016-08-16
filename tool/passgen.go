// friend!
// Copyright 2016 Joubin Houshyar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"passgen"
)

/// tool ////////////////////////////////////////////////////////////////

var policy = passgen.Printable
var size = 64
var cnt = 1
var seedPhrase string
var specials string

func init() {
	flag.StringVar(&seedPhrase, "input", seedPhrase, "seed phrase for OS agnostic random source")
	flag.IntVar(&size, "s", size, "password-length")
	flag.IntVar(&cnt, "n", cnt, "number of passwords to generate")
	flag.StringVar(&policy, "p", policy, "policy: {p:printable a:alpha n:num an:alphanum")
	flag.StringVar(&specials, "x", specials, "include special chars - should be quoted")
}

// REVU: good TODO is supporting specified special characters.
func main() {
	flag.Parse()

	spec := passgen.Spec{
		Policy:       policy,
		SeedPhrase:   seedPhrase,
		SpecialChars: specials,
	}
	generator, e := passgen.New(spec)
	if e != nil {
		os.Exit(onError("new generator", e))
	}
	defer generator.Dispose()

	for n := 0; n < cnt; n++ {
		password, e := generator.Generate(size)
		if e != nil {
			os.Exit(onError("new generator", e))
		}
		fmt.Println(password)
	}
}

func onError(s string, e error) int {
	fmt.Fprintf(os.Stderr, "err - %s - %s\n", s, e.Error())
	return 1
}
