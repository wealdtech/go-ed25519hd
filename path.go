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
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrElementTooLarge = errors.New("path element cannot be larger than 4294967295")

	pathRegex = regexp.MustCompile("^m((\\/[0-9]+')|(\\/[0-9]+'){2}|((\\/[0-9]+'){3}(\\/[0-9]+){0,2}))$")
)

func isValidPath(path string) bool {
	// Valid path format
	if !pathRegex.MatchString(path) {
		return false
	}

	// Valid elements
	_, err := elementsForPath(path)
	if err != nil {
		return false
	}

	return true
}

func elementsForPath(path string) ([]uint32, error) {
	elements := strings.Split(path, "/")

	results := make([]uint32, len(elements)-1)

	for i, element := range elements[1:] {
		result, err := strconv.ParseUint(strings.TrimRight(element, "'"), 10, 32)
		if err != nil {
			return nil, err
		}
		// Result must fit in uint32
		if result > 4294967295 {
			return nil, ErrElementTooLarge
		}
		results[i] = uint32(result)
	}

	return results, nil
}
