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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMnemonic(t *testing.T) {
	type test struct {
		mnemonic   string
		passphrase string
		err        error
		seed       []byte
	}
	tests := []test{
		{ // 0
			mnemonic: "awesome tide fiction sibling panther movie stable market cause coffee hair clarify celery lady transfer extend save parent decide hollow effort spin notice matter",
			seed:     _strToHex("ad019ec50032b8c5e9b0d51684931ef1a90cf290a725735ab0570e9cdee36abed2f698cd017ff0909ad9877846b44e4db452429f5d25edc6245d3a74baa724e1"),
		},
		{ // 1
			mnemonic:   "awesome tide fiction sibling panther movie stable market cause coffee hair clarify celery lady transfer extend save parent decide hollow effort spin notice matter",
			passphrase: "test",
			seed:       _strToHex("0fd51be372eb877281a9799acfc824108dad9c33b945af859fa3ddc96e3cc82c14a4279a02fccaf1ba9839f7013919cb30e0162317facc0652b6fb9541703f68"),
		},
		{ // 2
			mnemonic: "awesome tide fiction sibling panther movie stable market cause coffee hair clarify celery lady transfer extend save parent decide hollow effort spin notice notice",
			err:      fmt.Errorf("invalid mnemonic checksum"),
		},
	}

	for i, test := range tests {
		seed, err := SeedFromMnemonic(test.mnemonic, test.passphrase)
		require.Equal(t, test.err, err, fmt.Sprintf("Failed at test %d", i))
		require.Equal(t, test.seed, seed, fmt.Sprintf("Failed at test %d", i))
	}
}
