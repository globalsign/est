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

package basiclogger

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/globalsign/est"
)

// Logger is a basic logger implementing est.Logger.
type Logger struct {
	writer io.Writer
	fields []keyValue
}

// keyValue is a loosely-typed key-value pair.
type keyValue struct {
	key   string
	value interface{}
}

const (
	debugLabel = "DEBUG"
	errorLabel = "ERROR"
	infoLabel  = "INFO"
)

// Debug uses fmt.Sprint to construct and log a message.
func (l *Logger) Debug(v ...interface{}) {
	l.logw(debugLabel, fmt.Sprint(v...))
}

// Debugf uses fmt.Sprintf to log a formatted message.
func (l *Logger) Debugf(format string, v ...interface{}) {
	l.logw(debugLabel, fmt.Sprintf(format, v...))
}

// Debugw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (l *Logger) Debugw(msg string, keysAndValues ...interface{}) {
	l.logw(debugLabel, msg, keysAndValues...)
}

// Error uses fmt.Sprint to construct and log a message.
func (l *Logger) Error(v ...interface{}) {
	l.logw(errorLabel, fmt.Sprint(v...))
}

// Errorf uses fmt.Sprintf to log a formatted message.
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.logw(errorLabel, fmt.Sprintf(format, v...))
}

// Errorw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (l *Logger) Errorw(msg string, keysAndValues ...interface{}) {
	l.logw(errorLabel, msg, keysAndValues...)
}

// Info uses fmt.Sprint to construct and log a message.
func (l *Logger) Info(v ...interface{}) {
	l.logw(infoLabel, fmt.Sprint(v...))
}

// Infof uses fmt.Sprintf to log a formatted message.
func (l *Logger) Infof(format string, v ...interface{}) {
	l.logw(infoLabel, fmt.Sprintf(format, v...))
}

// Infow logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (l *Logger) Infow(msg string, keysAndValues ...interface{}) {
	l.logw(infoLabel, msg, keysAndValues...)
}

// With adds a variadic number of key-values pairs to the logging context. The
// first element of the pair is used as the field key and should be a string.
// Passing a non-string key or passing an orphaned key panics.
func (l *Logger) With(args ...interface{}) est.Logger {
	if len(args)%2 != 0 {
		panic("number of arguments is not a multiple of 2")
	}

	newLogger := &Logger{
		writer: l.writer,
		fields: l.fields,
	}

	for i := 0; i < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			panic(fmt.Sprintf("argument %d is not a string", i))
		}

		newLogger.fields = append(newLogger.fields, keyValue{key: key, value: args[i+1]})
	}

	return newLogger
}

// logw is the common implementation for all logging methods.
func (l *Logger) logw(level string, msg string, keysAndValues ...interface{}) {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("%s\t%s", time.Now().UTC().Format(time.RFC3339Nano), level))
	if _, file, line, ok := runtime.Caller(2); ok {
		builder.WriteString(fmt.Sprintf("\t%s/%s:%d", filepath.Base(filepath.Dir(file)), filepath.Base(file), line))
	}
	builder.WriteString(fmt.Sprintf("\t%s", msg))

	l.stringifyFields(&builder, keysAndValues...)

	builder.WriteString("\n")

	l.writer.Write([]byte(builder.String()))
}

// stringifyFields formats a logger's context fields, plus any extra key-value
// pairs, as a braced, comma-separated, quoted "key":"value" list, and writes
// it to the provided string builder.
func (l *Logger) stringifyFields(builder *strings.Builder, extra ...interface{}) {
	if len(extra)%2 != 0 {
		panic("number of arguments is not a multiple of 2")
	}

	// Make a copy of the logger's context fields, and add any extra key-value
	// pairs to it.
	kvs := l.fields
	for i := 0; i < len(extra); i += 2 {
		key, ok := extra[i].(string)
		if !ok {
			panic(fmt.Sprintf("argument %d is not a string", i))
		}

		kvs = append(kvs, keyValue{key: key, value: extra[i+1]})
	}

	if len(kvs) == 0 {
		return
	}

	// Format and write the key-value pairs.
	for i, kv := range kvs {
		if i == 0 {
			builder.WriteString("\t{")
		} else {
			builder.WriteString(", ")
		}
		builder.WriteString(fmt.Sprintf(`%s: %s`, strconv.Quote(kv.key),
			strconv.Quote(fmt.Sprintf("%v", kv.value))))
	}

	builder.WriteString("}")
}

// New creates a new basic logger which writes to the specified writer.
func New(w io.Writer) est.Logger {
	return &Logger{
		writer: w,
	}
}
