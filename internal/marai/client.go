package marai

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Socket       string
	User         string
	PasswordFile string
	Timeout      time.Duration
}

type Client struct {
	cfg      Config
	password string
}

func New(cfg Config) (*Client, error) {
	if cfg.Socket == "" || cfg.User == "" || cfg.PasswordFile == "" || cfg.Timeout <= 0 {
		return nil, errors.New("socket, user, password file, and timeout are required")
	}
	value, err := os.ReadFile(cfg.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("read marai password: %w", err)
	}
	password := strings.TrimRight(string(value), "\r\n")
	if password == "" {
		return nil, errors.New("marai password is empty")
	}
	return &Client{cfg: cfg, password: password}, nil
}

func (c *Client) Encrypt(ctx context.Context, key string, plaintext []byte) ([]byte, error) {
	reply, err := c.call(ctx, "FCALL", "kms_encrypt", "0", key, plaintext)
	return bulk(reply, err)
}

func (c *Client) Decrypt(ctx context.Context, key string, envelope []byte) ([]byte, error) {
	reply, err := c.call(ctx, "FCALL", "kms_decrypt", "0", key, envelope)
	return bulk(reply, err)
}

func (c *Client) GenerateDataKey(ctx context.Context, key string) ([]byte, []byte, error) {
	reply, err := c.call(ctx, "FCALL", "kms_generate_data_key", "0", key)
	if err != nil {
		return nil, nil, err
	}
	values, ok := reply.([]any)
	if !ok || len(values) != 2 {
		return nil, nil, errors.New("unexpected generate-data-key reply")
	}
	plaintext, ok1 := values[0].([]byte)
	wrapped, ok2 := values[1].([]byte)
	if !ok1 || !ok2 {
		return nil, nil, errors.New("unexpected generate-data-key values")
	}
	return plaintext, wrapped, nil
}

// Ping is Atman's readiness probe for the cryptographic authority, not merely
// Redis process liveness. A quiesced, exported, dead, or bootstrap-only Marai
// process must not keep the HTTP gateway ready for application traffic.
func (c *Client) Ping(ctx context.Context) error {
	reply, err := c.call(ctx, "KMS.STATUS")
	if err != nil {
		return err
	}
	values, ok := reply.([]any)
	if !ok || len(values) != 5 {
		return errors.New("unexpected marai status reply")
	}
	state, ok := values[0].(string)
	if !ok {
		if raw, rawOK := values[0].([]byte); rawOK {
			state = string(raw)
			ok = true
		}
	}
	if !ok || state != "active" {
		if state == "" {
			state = "unknown"
		}
		return fmt.Errorf("marai authority is %s", state)
	}
	return nil
}

func bulk(reply any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	value, ok := reply.([]byte)
	if !ok {
		return nil, errors.New("unexpected bulk reply")
	}
	return value, nil
}

func (c *Client) call(ctx context.Context, args ...any) (any, error) {
	dialer := net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.cfg.Socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(c.cfg.Timeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	if err := writeCommand(conn, "AUTH", c.cfg.User, c.password); err != nil {
		return nil, err
	}
	if _, err := readReply(reader); err != nil {
		return nil, fmt.Errorf("authenticate to marai: %w", err)
	}
	if err := writeCommand(conn, args...); err != nil {
		return nil, err
	}
	return readReply(reader)
}

func writeCommand(w io.Writer, args ...any) error {
	var request bytes.Buffer
	fmt.Fprintf(&request, "*%d\r\n", len(args))
	for _, arg := range args {
		var value []byte
		switch typed := arg.(type) {
		case string:
			value = []byte(typed)
		case []byte:
			value = typed
		default:
			return fmt.Errorf("unsupported argument type %T", arg)
		}
		fmt.Fprintf(&request, "$%d\r\n", len(value))
		request.Write(value)
		request.WriteString("\r\n")
	}
	_, err := w.Write(request.Bytes())
	return err
}

type redisError string

func (e redisError) Error() string { return string(e) }

func readReply(reader *bufio.Reader) (any, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("malformed Redis reply")
	}
	payload := line[1 : len(line)-2]
	switch line[0] {
	case '+':
		return payload, nil
	case '-':
		return nil, redisError(payload)
	case ':':
		return strconv.ParseInt(payload, 10, 64)
	case '$':
		length, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if length < 0 {
			return nil, nil
		}
		value := make([]byte, length+2)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		if !bytes.Equal(value[length:], []byte("\r\n")) {
			return nil, errors.New("malformed Redis bulk reply")
		}
		return value[:length], nil
	case '*':
		length, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		values := make([]any, length)
		for i := range values {
			values[i], err = readReply(reader)
			if err != nil {
				return nil, err
			}
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unsupported Redis reply %q", line[0])
	}
}
