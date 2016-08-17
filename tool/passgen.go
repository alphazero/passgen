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
var noRep bool

func init() {
	flag.StringVar(&seedPhrase, "seed", seedPhrase, "(min 8 char) seed phrase for random source - required")
	flag.IntVar(&size, "s", size, "password-length")
	flag.IntVar(&cnt, "n", cnt, "number of passwords to generate")
	flag.StringVar(&policy, "p", policy, "policy: {p:printable a:alpha n:num an:alphanum")
	flag.StringVar(&specials, "x", specials, "include special chars - should be quoted")
	flag.BoolVar(&noRep, "norep", noRep, "no repeated sequences")
}

func main() {
	flag.Parse()

	if seedPhrase == "" {
		os.Exit(onError("usage", fmt.Errorf("cmdline option 'seed' is required.")))
	}

	spec := passgen.Spec{
		Policy:       policy,
		SeedPhrase:   seedPhrase,
		SpecialChars: specials,
		NoRep:        noRep,
	}
	generator, e := passgen.New(spec)
	if e != nil {
		os.Exit(onError("new generator", e))
	}

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
