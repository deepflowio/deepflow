package logger

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type RSyslogWriter struct {
	tag      string
	hostname string
	network  string
	raddr    string
	header   string

	mu   sync.Mutex // guards conn
	conn net.Conn
}

func (w *RSyslogWriter) connect() (err error) {
	if w.conn != nil {
		// ignore err from close, it makes sense to continue anyway
		w.conn.Close()
		w.conn = nil
	}

	if w.network != "" {
		var c net.Conn
		c, err = net.Dial(w.network, w.raddr)
		if err == nil {
			w.conn = c
			if w.hostname == "" {
				w.hostname = c.LocalAddr().String()
			}
		}
	}
	return
}

// Close closes a connection to the syslog daemon.
func (w *RSyslogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		err := w.Close()
		w.conn = nil
		return err
	}
	return nil
}

// Write sends a log message to the syslog daemon.
func (w *RSyslogWriter) Write(b []byte) (int, error) {
	return w.writeAndRetry(string(b))
}

func (w *RSyslogWriter) writeAndRetry(s string) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		if n, err := w.write(s); err == nil {
			return n, err
		}
	}
	if err := w.connect(); err != nil {
		return 0, err
	}
	return w.write(s)
}

func (w *RSyslogWriter) write(msg string) (int, error) {
	// ensure it ends in a \n
	nl := ""
	if !strings.HasSuffix(msg, "\n") {
		nl = "\n"
	}

	err := w.writeString(w.hostname, w.tag, msg, nl)
	if err != nil {
		return 0, err
	}
	// Note: return the length of the input, not the number of
	// bytes printed by Fprintf, because this must behave like
	// an io.Writer.
	return len(msg), nil
}

func (w *RSyslogWriter) writeString(hostname, tag, msg, nl string) error {
	timestamp := time.Now().Format(time.RFC3339)
	_, err := fmt.Fprintf(w.conn, "%s%s %s %s[%d]: %s%s", w.header,
		timestamp, hostname,
		tag, os.Getpid(), msg, nl)
	return err
}

func NewRsyslogWriter(network, raddr string, tag, header string) *RSyslogWriter {
	if tag == "" {
		tag = os.Args[0]
	}
	hostname, _ := os.Hostname()

	w := &RSyslogWriter{
		tag:      tag,
		hostname: hostname,
		network:  network,
		raddr:    raddr,
		header:   header,
	}
	return w
}
