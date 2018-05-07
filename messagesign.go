// Copyright 2014 The Monero Developers.
// All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package urs

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	//"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// Flags
var gFlag = flag.String("set-generate", "", "Generates to a new keypair; g|set-generate [filename]")
var vtFlag = flag.String("verify-text", "", "Verify a text message; v|verify-text [filename]")
var vbFlag = flag.String("verify-bin", "", "Verify a binary message; b|verify-bin [filename]")
var stFlag = flag.String("sign-text", "", "Sign a binary message; s|verify-bin [filename]")
var sbFlag = flag.String("sign-bin", "", "Sign a text message; z|verify-bin [filename]")
var krFlag = flag.String("keyring", "", "Load a keyring of pubkeys; k|keyring [filename]")
var kpFlag = flag.String("keypair", "", "Load a keypair to sign from; p|keypair [filename]")
var sigFlag = flag.String("sig", "", "Load a Base58 signature to verify; S|sig [filename]")
var blindFlag = flag.Bool("blind", false, "Enable signature blinding (non-unique!); B|blind")

func init() {
	// Short version flags
	flag.StringVar(gFlag, "g", "", "Generates to a new keypair; g|set-generate [filename]")
	flag.StringVar(vtFlag, "v", "", "Verify a text message; v|verify-text [filename]")
	flag.StringVar(vbFlag, "b", "", "Verify a binary message; b|verify-bin [filename]")
	flag.StringVar(stFlag, "s", "", "Sign a text message; s|verify-bin [filename]")
	flag.StringVar(sbFlag, "z", "", "Sign a binary message; z|verify-bin [filename]")
	flag.StringVar(krFlag, "k", "", "Load a keyring of pubkeys; k|keyring [filename]")
	flag.StringVar(kpFlag, "p", "", "Load a keypair to sign from; p|keypair [filename]")
	flag.StringVar(sigFlag, "S", "", "Load a Base58 signature to verify; S|sig [filename]")
	flag.BoolVar(blindFlag, "B", false, "Enable signature blinding (non-unique!); B|blind")
}

// generateKeyPair generates and stores an ECDSA keypair to a file.
func generateKeyPair(filename string) error {
	// Generate keypairs.
	aKeypair, err := ecdsa.GenerateKey(btcec.S256(), crand.Reader)
	if err != nil {
		return err
	}
	pubkeyBtcec := btcec.PublicKey{aKeypair.PublicKey.Curve,
		aKeypair.PublicKey.X,
		aKeypair.PublicKey.Y}
	keypairBtcec := btcec.PrivateKey{aKeypair.PublicKey, aKeypair.D}

	// Create a map to json marshal
	keypairMap := make(map[string]string)
	keypairMap["pubkey"] = hex.EncodeToString(pubkeyBtcec.SerializeCompressed())
	keypairMap["privkey"] = hex.EncodeToString(keypairBtcec.Serialize())

	// Store the address in case anyone wants to use it for BTC
	pkh, err := btcutil.NewAddressPubKey(pubkeyBtcec.SerializeCompressed(),
		&chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	keypairMap["address"] = pkh.EncodeAddress()

	b, err := json.Marshal(keypairMap)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, b, 0644)
	if err != nil {
		return err
	}

	return nil
}