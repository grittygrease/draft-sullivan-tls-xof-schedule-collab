// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// stockserver is the HKDF-only peer for the patched crypto/tls test
// TestXOFInteropStockServer.
// Build this file with a stock Go 1.24 or later toolchain.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: %s port", os.Args[0])
	}
	port, err := strconv.ParseUint(os.Args[1], 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid port %q", os.Args[1])
	}
	cert, err := certificate()
	if err != nil {
		return err
	}
	l, err := tls.Listen("tcp4", net.JoinHostPort("127.0.0.1", os.Args[1]), &tls.Config{
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{"deck-demo"},
		SessionTicketsDisabled: true,
	})
	if err != nil {
		return err
	}
	defer l.Close()
	fmt.Println("listening")
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		if err := echo(conn.(*tls.Conn)); err != nil {
			// Keep serving after a client rejects the HKDF fallback.
			fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		}
	}
}

func echo(conn *tls.Conn) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if _, err := io.WriteString(conn, line); err != nil {
		return err
	}
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial("deck-demo exporter", []byte("context"), 32)
	if err != nil {
		return err
	}
	fmt.Printf("exporter: %x\n", exporter)
	return nil
}

func certificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
