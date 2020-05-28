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

// Logger is an interface for an EST server logger.
type Logger interface {
	// Errorf uses fmt.Sprintf to log a formatted message.
	Errorf(format string, args ...interface{})

	// Errorw logs a message with some additional context. The variadic
	// key-value pairs are treated as they are in With.
	Errorw(format string, keysAndValues ...interface{})

	// Infof uses fmt.Sprintf to log a formatted message.
	Infof(format string, args ...interface{})

	// Infow logs a message with some additional context. The variadic
	// key-value pairs are treated as they are in With.
	Infow(format string, keysAndValues ...interface{})

	// With adds a variadic number of key-values pairs to the logging context.
	// The first element of the pair is used as the field key and should be a
	// string. Passing a non-string key or passing an orphaned key panics.
	With(keysAndValues ...interface{}) Logger
}

// nopLogger is a do-nothing logger which can be used if no logger is
// provided to the EST server.
type nopLogger struct{}

func (l *nopLogger) Errorf(format string, args ...interface{}) {}

func (l *nopLogger) Errorw(msg string, keysAndValues ...interface{}) {}

func (l *nopLogger) Infof(format string, args ...interface{}) {}

func (l *nopLogger) Infow(msg string, keysAndValues ...interface{}) {}

func (l *nopLogger) With(keysAndValues ...interface{}) Logger {
	return l
}

func newNOPLogger() Logger {
	return &nopLogger{}
}
