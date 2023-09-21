package csbouncer

import (
  "io"
  "bytes"
)

type SSEReader struct {
	reader io.Reader
}

func newSSEReader(reader io.Reader) *SSEReader {
	return &SSEReader{
          reader: reader,
        }
}

func alpha(r byte) byte {
  if r != 0x1a && r > 0x00 { 
    return r
  }
  if r == 0x1a {
    return 0x1a
  }
  return 0
}

func (a *SSEReader) Read(p []byte) (int, error) {	 
        for {
          buf := make([]byte, len(p))
          n, err := a.reader.Read(buf)
          if err != nil {
                  return n, err
          }

          buff := make([]byte, len(p))
          for i := 0; i < n; i++ {
            if char := alpha(buf[i]); char != 0 {
              buff[i] = char
            }
          }

          non_zero_count := len(buff) - bytes.Count(buff, []byte("\x00"))
          p_non_zero_count := len(p) - bytes.Count(p, []byte("\x00"))

          p = append(p[:p_non_zero_count], buff[:non_zero_count]...)
          if p[len(p)-1] == 0x1a {
            break
          }
        }	

        // Remove the EOF byte
        p = bytes.Trim(p, "\x1a")

        return len(p), nil
}
