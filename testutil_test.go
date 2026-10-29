package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"
)

func genTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func bigFrom(n int64) *big.Int     { return big.NewInt(n) }
func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
func nowMinus() time.Time          { return time.Now().Add(-time.Hour) }
func nowPlus() time.Time           { return time.Now().Add(24 * time.Hour) }
func randReader() io.Reader        { return rand.Reader }
