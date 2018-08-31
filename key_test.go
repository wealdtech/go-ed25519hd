// Copyright © 2018 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ed25519hd

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func _strToHex(input string) []byte {
	result, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return result
}

func TestDeriveKey(t *testing.T) {
	type test struct {
		seed   []byte
		path   string
		err    error
		pubKey []byte
	}

	tests := []test{
		{ // 0
			err: fmt.Errorf("invalid path"),
		},
		{ // 1
			path: "m/44'/1901'/0'",
			err:  fmt.Errorf("seed must be 64 bytes (passed 0)"),
		},
		{ // 2
			seed:   _strToHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			path:   "m/44'/1901'/0'",
			pubKey: _strToHex("46d34d252e3d0e4ce90169baf62947ead31d2003488ae00fd30b4eaf0ab1965d"),
		},
		{ // 3
			seed:   _strToHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			path:   "m/44'/1901'/0'/0",
			pubKey: _strToHex("6815638e0ad2de6f6a63fd99299f1886b9e91749d8d4871467994fe20291bbe8"),
		},
		{ // 4
			seed:   _strToHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			path:   "m/44'/1901'/0'/0/0",
			pubKey: _strToHex("cd1f83d6d5fbe3008598ed167aca369f53f2a966b17e2e8b90a8800d913a9d87"),
		},
		{ // 5
			seed:   _strToHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			path:   "m/44'/1901'/0'/0/1",
			pubKey: _strToHex("acbe855bd3966736a2dbe8f537b2e52566d719578b92dd2f78be4af5f3c769e7"),
		},
		{ // 6
			seed:   _strToHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			path:   "m/44'/1901'/1'",
			pubKey: _strToHex("1a7462f6d2fc6603f78468a64ab2cd2b51ab8444350ed0024cd64ee6e9cebb0b"),
		},
		{ // 7
			// BIP-39 mnemonic: knife blouse guide fabric fiction dry shiver trap wrong learn paddle thunder hood version rebel bike expect magic parent foil cushion excess scout barely
			seed:   _strToHex("ad41ba61debefb8c24557a17ea372f7a76da3fab57e4d2b27e290d6b0c6d97e37d0bcdb0c26cdb530bea74beeade30ccea00bed7fc503f185297459653cc4f33"),
			path:   "m/44'/1901'/0'",
			pubKey: _strToHex("f19abf1e05870d93e5f9df15c7b0cdde46dc60814d7033ac7a308b400e4d9707"),
		},
		{ // 8
			// BIP-39 mnemonic: knife blouse guide fabric fiction dry shiver trap wrong learn paddle thunder hood version rebel bike expect magic parent foil cushion excess scout barely
			seed:   _strToHex("ad41ba61debefb8c24557a17ea372f7a76da3fab57e4d2b27e290d6b0c6d97e37d0bcdb0c26cdb530bea74beeade30ccea00bed7fc503f185297459653cc4f33"),
			path:   "m/44'/1901'/1'",
			pubKey: _strToHex("28e092dd31285d014f74a9d57d1d91f86dcca3af8c3e13a4558fd7889b999186"),
		},
	}

	for i, test := range tests {
		key, err := DeriveKey(test.seed, test.path)
		require.Equal(t, test.err, err, fmt.Sprintf("Failed at test %d", i))
		if test.err == nil {
			pubKey, err := key.PublicKey()
			require.Nil(t, err, fmt.Sprintf("Failed at test %d", i))
			require.Equal(t, test.pubKey, pubKey, fmt.Sprintf("Failed at test %d", i))
		}
	}
}
