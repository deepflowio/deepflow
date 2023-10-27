package common

import (
	"bytes"
	"compress/gzip"
	"io"
)

func GzipDecompress(bs []byte) ([]byte, error) {
	var err error
	if len(bs) < 2 {
		return bs, nil
	} else if bs[0] == 0x1f && bs[1] == 0x8b {
		// jfr magic header: https://github.com/grafana/jfr-parser/blob/main/parser/parser.go#L14
		// after gzip compress, the first 2 bytes are 0x1f8b
		var gzipr *gzip.Reader
		gzipr, err = gzip.NewReader(bytes.NewReader(bs))
		defer gzipr.Close()
		if err != nil {
			return nil, err
		}
		buf := bytes.NewBuffer(nil)
		if _, err = io.Copy(buf, gzipr); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	} else {
		return bs, nil
	}
}
