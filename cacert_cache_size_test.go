/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package est

import (
	"strconv"
	"testing"
)

func TestCACertCacheSize(t *testing.T) {
	t.Parallel()

	c := newCACertCache(nil)
	for i := 0; i < maxCacheEntries+10; i++ {
		c.addSync(strconv.Itoa(i), nil)
	}

	if n := len(c.cache); n != maxCacheEntries {
		t.Fatalf("got %d cache entries, want %d", n, maxCacheEntries)
	}

	// The newest entry is always kept.
	if _, ok := c.cache[strconv.Itoa(maxCacheEntries+9)]; !ok {
		t.Fatal("newest entry not in cache")
	}
}
