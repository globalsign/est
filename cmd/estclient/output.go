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

package main

import (
	"fmt"
	"io"
	"os"
)

// maybeRedirect returns the provided io.Writer if filename is the empty
// string, otherwise it opens and returns the named file, creating it with
// the specified permissions if it doesn't exist. The caller is responsible
// for closing the file with the returned function.
//
// On Unix, existing regular files lose read and write permissions not
// granted by perm before truncation.
func maybeRedirect(w io.Writer, filename string, perm os.FileMode) (io.Writer, func() error, error) {
	if filename == "" {
		return w, func() error { return nil }, nil
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("failed to stat output file: %v", err)
	}
	if fi.Mode().IsRegular() {
		if extra := fi.Mode().Perm() &^ perm & 0666; extra != 0 {
			if err := f.Chmod(fi.Mode().Perm() &^ extra); err != nil {
				f.Close()
				return nil, nil, fmt.Errorf("failed to restrict output file permissions: %v", err)
			}
		}
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("failed to truncate output file: %v", err)
		}
	}

	return f, f.Close, nil
}
