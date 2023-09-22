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
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// Key is an ED255-19 key.
type Key struct {
	key       []byte
	chainCode []byte
}

var (
	// ErrUnhardenedElement is returned when an element in a path is not hardened.
	ErrUnhardenedElement = errors.New("elements must be hardened")
	// ErrInvalidPath is returned when a path is invalid.
	ErrInvalidPath = errors.New("invalid path")

	hardenedOffset = uint32(0x80000000)
)

// MasterKeyFromSeed generates a master key given a seed.
// The seed must be 64 bytes to be valid.
func MasterKeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("seed must be 64 bytes (passed %d)", len(seed))
	}

	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	_, err := mac.Write(seed)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write seed")
	}
	result := mac.Sum(nil)

	return &Key{
		key:       result[0:32],
		chainCode: result[32:64],
	}, nil
}

func deriveKey(key *Key, index uint32) (*Key, error) {
	if index < hardenedOffset {
		return nil, ErrUnhardenedElement
	}

	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, index)
	data := append([]byte{0x0}, key.key...)
	data = append(data, iBytes...)

	hmac := hmac.New(sha512.New, key.chainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write data")
	}
	sum := hmac.Sum(nil)
	newKey := &Key{
		key:       sum[0:32],
		chainCode: sum[32:64],
	}

	return newKey, nil
}

// PublicKey returns the public key for a derived private key.
func (k *Key) PublicKey() ([]byte, error) {
	reader := bytes.NewReader(k.key)
	pub, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key")
	}

	return pub[:], nil
}

// Seed returns a copy of the seed for a derived path.
func (k *Key) Seed() [32]byte {
	var seed [32]byte
	copy(seed[:], k.key)

	return seed
}
