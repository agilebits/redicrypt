package redicrypt

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/gomodule/redigo/redis"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"
)

// RediCrypt is a redis based cache storage
type RediCrypt struct {
	Addr      string
	Conn      redis.Conn
	certnames []string
}

// NewRediCryptWithAddr is a constructor for a redicrypt instance with a specific address
func NewRediCryptWithAddr(addr string) (*RediCrypt, error) {
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		return nil, errors.Wrap(err, "NewRediCryptWithAddr failed to Dial")
	}

	rc := &RediCrypt{
		Addr: addr,
		Conn: c,
	}

	return rc, nil
}

// Get reads certificate data from redis.
func (rc *RediCrypt) Get(ctx context.Context, name string) ([]byte, error) {
	key := redisKeyForName(name)
	fmt.Println("redicrypt: getting cert for key " + key)

	data := ""
	done := make(chan error)

	go func() {
		var err error

		data, err = redis.String(rc.Conn.Do("GET", key))
		if err == redis.ErrNil {
			done <- autocert.ErrCacheMiss
		} else {
			done <- err
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, err
		}
	}

	certBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.Wrap(err, "Get failed to DecodeString")
	}

	return certBytes, nil
}

// Put writes certificate data to redis.
func (rc *RediCrypt) Put(ctx context.Context, name string, data []byte) error {
	key := redisKeyForName(name)
	fmt.Println("redicrypt: writing cert for key ", key)
	rc.certnames = append(rc.certnames, name)

	encodedData := base64.StdEncoding.EncodeToString(data)
	done := make(chan error)

	go func() {
		select {
		case <-ctx.Done():
			// Don't overwrite the file if the context was canceled.
		default:
			_, err := rc.Conn.Do("SET", key, encodedData)
			done <- err
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete removes the specified redis key.
func (rc *RediCrypt) Delete(ctx context.Context, name string) error {
	key := redisKeyForName(name)
	fmt.Println("redicrypt: deleting cert for key ", key)
	done := make(chan error)

	go func() {
		_, err := rc.Conn.Do("DELETE", key)
		done <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
	}

	return nil
}

// GetAll returns all stored certificates
func (rc *RediCrypt) GetAll(ctx context.Context) ([][]byte, error) {
	fmt.Println("redicrypt: getting all known certs")

	certs := [][]byte{}

	for _, n := range rc.certnames {
		cert, err := rc.Get(ctx, redisKeyForName(n))
		if err != nil {
			return nil, errors.Wrapf("unable to get cert for '%s'", n)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func redisKeyForName(name string) string {
	return fmt.Sprintf("redicrypt/%s", name)
}
