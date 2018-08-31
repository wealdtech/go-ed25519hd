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

func TestValidPaths(t *testing.T) {
	type test struct {
		path  string
		valid bool
	}
	tests := []test{
		{ // 0
			path:  "m",
			valid: false,
		},
		{ // 1
			path:  "m/44",
			valid: false,
		},
		{ // 2
			path:  "m/44'",
			valid: true,
		},
		{ // 3
			path:  "m/44'/",
			valid: false,
		},
		{ // 4
			path:  "m/44'/1901",
			valid: false,
		},
		{ // 5
			path:  "m/44'/1901'",
			valid: true,
		},
		{ // 5
			path:  "m/44'/1901'/",
			valid: false,
		},
		{ // 6
			path:  "m/44'/1901'/0",
			valid: false,
		},
		{ // 7
			path:  "m/44'/1901'/0'",
			valid: true,
		},
		{ // 8
			path:  "m/44'/1901'/0'/",
			valid: false,
		},
		{ // 9
			path:  "m/44'/1901'/0'/0'",
			valid: false,
		},
		{ // 10
			path:  "m/44'/1901'/0'/0",
			valid: true,
		},
		{ // 11
			path:  "m/44'/1901'/0'/0/",
			valid: false,
		},
		{ // 12
			path:  "m/44'/1901'/0'/0/0",
			valid: true,
		},
		{ // 13
			path:  "m/44'/1901'/0'/0/0/0",
			valid: false,
		},
		{ // 13
			path:  "m/44'/4294967295'",
			valid: true,
		},
		{ // 13
			path:  "m/44'/4294967296'",
			valid: false,
		},
	}

	for i, test := range tests {
		valid := isValidPath(test.path)
		require.Equal(t, test.valid, valid, fmt.Sprintf("Failed at test %d", i))
	}
}
