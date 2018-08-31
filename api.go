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
	"bytes"

	"github.com/agl/ed25519"
)

// Keys generates the Ed25519 public and private keys given a seed and a path.
// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
func Keys(seed []byte, path string) ([]byte, []byte, error) {
	key, err := DeriveKey(seed, path)
	if err != nil {
		return nil, nil, err
	}

	reader := bytes.NewReader(key.key)
	pub, priv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, nil, err
	}
	return pub[:], priv[:], err
}

// DeriveKey derives a key given a seed and a derivation path
func DeriveKey(seed []byte, path string) (*Key, error) {
	if !isValidPath(path) {
		return nil, ErrInvalidPath
	}

	key, err := MasterKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}

	elements, err := elementsForPath(path)
	if err != nil {
		return nil, err
	}

	for _, element := range elements {
		// We operate on hardened elements
		hardenedElement := element + hardenedOffset
		key, err = deriveKey(key, hardenedElement)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}
