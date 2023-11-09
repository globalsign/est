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

package basiclogger_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/haritzsaiz/est/internal/basiclogger"
)

func TestLogger(t *testing.T) {
	t.Parallel()

	buf := bytes.NewBuffer([]byte{})
	plain := basiclogger.New(buf).(*basiclogger.Logger)
	decorated := basiclogger.New(buf).With("With", "Present").(*basiclogger.Logger)

	var testcases = []struct {
		logfunc func()
		level   string
		msg     string
		fields  string
	}{
		{
			logfunc: func() { plain.Debug("debug message") },
			level:   "DEBUG",
			msg:     "debug message",
		},
		{
			logfunc: func() { plain.Debugf("formatted %d", 42) },
			level:   "DEBUG",
			msg:     "formatted 42",
		},
		{
			logfunc: func() { plain.Debugw("another message", "this", 42, "that", false) },
			level:   "DEBUG",
			msg:     "another message",
			fields:  `{"this": "42", "that": "false"}`,
		},
		{
			logfunc: func() { decorated.Error("error message") },
			level:   "ERROR",
			msg:     "error message",
			fields:  `{"With": "Present"}`,
		},
		{
			logfunc: func() { decorated.Errorf("formatted %t", true) },
			level:   "ERROR",
			msg:     "formatted true",
			fields:  `{"With": "Present"}`,
		},
		{
			logfunc: func() { decorated.Errorw("messages?", "red balloons", 99) },
			level:   "ERROR",
			msg:     "messages?",
			fields:  `{"With": "Present", "red balloons": "99"}`,
		},
		{
			logfunc: func() { decorated.Info("info message") },
			level:   "INFO",
			msg:     "info message",
			fields:  `{"With": "Present"}`,
		},
		{
			logfunc: func() { decorated.Infof("formatted %s", "world") },
			level:   "INFO",
			msg:     "formatted world",
			fields:  `{"With": "Present"}`,
		},
		{
			logfunc: func() { decorated.Infow("more messages", "some", "nonsense") },
			level:   "INFO",
			msg:     "more messages",
			fields:  `{"With": "Present", "some": "nonsense"}`,
		},
	}

	for i, tc := range testcases {
		tc := tc

		t.Run(strconv.Itoa(i+1), func(t *testing.T) {
			buf.Reset()

			tc.logfunc()

			values := strings.Split(buf.String(), "\t")

			if tc.fields == "" {
				if len(values) != 4 {
					t.Fatalf("got %d values, want %d", len(values), 4)
				}
			} else {
				if len(values) != 5 {
					t.Fatalf("got %d values, want %d", len(values), 5)
				}
			}

			if _, err := time.Parse(time.RFC3339Nano, values[0]); err != nil {
				t.Fatalf("failed to parse datetime: %v", err)
			}

			if got := values[1]; got != tc.level {
				t.Fatalf("got level %s, want %s", got, tc.level)
			}

			if got := values[2]; !strings.HasPrefix(got, "basiclogger/logger_test.go:") {
				t.Fatalf("unexpected file:line: %s", got)
			}

			if got := strings.TrimSpace(values[3]); got != tc.msg {
				t.Fatalf("got message %q, want %q", got, tc.msg)
			}

			if tc.fields != "" {
				if got := strings.TrimSpace(values[4]); got != tc.fields {
					t.Fatalf("got fields %q, want %q", got, tc.fields)
				}
			}
		})
	}
}
