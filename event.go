/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package csbouncer

import (
	"io"
        "bytes"
)

// EventStreamReader scans an io.Reader looking for EventStream messages.
type EventStreamReader struct {
  reader        *SSEReader 
  maxBufferSize int
}

// NewEventStreamReader creates an instance of EventStreamReader.
func NewEventStreamReader(eventStream io.Reader, maxBufferSize int) *EventStreamReader {
        reader := newSSEReader(eventStream)
	return &EventStreamReader{
          reader:   reader,
          maxBufferSize: maxBufferSize,
        }
}

// ReadEvent scans the EventStream for events.
func (e *EventStreamReader) ReadEvent() ([]byte, error) {
  buff := make([]byte, e.maxBufferSize)
  _, err := e.reader.Read(buff)
  if err != nil {
    return nil, err
  }
  buff_non_zero_count := len(buff) - bytes.Count(buff, []byte("\x00"))
  buff = buff[:buff_non_zero_count]
  buff = bytes.Trim(buff, "\x1a")
  return buff, nil
}
