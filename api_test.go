// Copyright © 2018, 2023 Weald Technology Trading.
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeys(t *testing.T) {
	type test struct {
		name    string
		seed    []byte
		path    string
		err     string
		privKey []byte
	}

	tests := []test{
		{
			name: "Empty",
			err:  "invalid path",
		},
		{
			name: "NoSeed",
			path: "m/44'/1901'/0'",
			err:  "seed must be 64 bytes (passed 0)",
		},
		{
			name:    "Good",
			seed:    _strToHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			path:    "m/44'/1901'/0'",
			privKey: _strToHex("5027fcca089691ad5fedfb65b4d165a1991818b25cbcc995a8b17adfc85549e446d34d252e3d0e4ce90169baf62947ead31d2003488ae00fd30b4eaf0ab1965d"),
		},
		{
			name: "KnownMnemonic",
			// BIP-39 mnemonic: knife blouse guide fabric fiction dry shiver trap wrong learn paddle thunder hood version rebel bike expect magic parent foil cushion excess scout barely
			seed:    _strToHex("ad41ba61debefb8c24557a17ea372f7a76da3fab57e4d2b27e290d6b0c6d97e37d0bcdb0c26cdb530bea74beeade30ccea00bed7fc503f185297459653cc4f33"),
			path:    "m/44'/1901'/0'",
			privKey: _strToHex("65430d794b49b570f7e51f9e2078bd7e3fe67e8866ded3b7535f13b5b631f5bcf19abf1e05870d93e5f9df15c7b0cdde46dc60814d7033ac7a308b400e4d9707"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, privKey, err := Keys(test.seed, test.path)
			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.privKey, privKey)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}
