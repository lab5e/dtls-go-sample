package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v2"
)

const (
	host     = "192.168.1.108"
	port     = 1234
	certFile = "cert.crt"
	keyFile  = "key.pem"
)

func main() {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Printf("Error reading cert file: %v\n", err)
		os.Exit(1)
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("Error reading key file: %v\n", err)
		os.Exit(1)
	}

	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		fmt.Printf("Could not create key pair: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded certificate")

	pool, err := loadCertPool(certBytes)
	if err != nil {
		fmt.Printf("Error loading certificate pool: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded pool with %d certificates \n", len(pool.Subjects()))

	tlsConfig := &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		RootCAs:            pool,
		ClientCAs:          pool,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 30*time.Second)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}

	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, tlsConfig)
	if err != nil {
		fmt.Printf("Error dialing server: %v\n", err)
		os.Exit(1)
	}

	defer dtlsConn.Close()

	payload := []byte("This Is A Go Sample Message")

	dtlsConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err = dtlsConn.Write(payload)
	if err != nil {
		fmt.Printf("Error writing DTLS packet: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent %d bytes to service\n", len(payload))
	dtlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _ := dtlsConn.Read(payload)
	if n > 0 {
		fmt.Printf("Got %d bytes from service\n", n)
	}
	time.Sleep(time.Second)
}

func loadCertPool(pemBytes []byte) (*x509.CertPool, error) {
	var certs []*x509.Certificate

	block, remain := pem.Decode(pemBytes)
	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
		block, remain = pem.Decode(remain)
	}
	pool := x509.NewCertPool()
	for _, crt := range certs {
		if isIntermediateCertificate(crt) {
			pool.AddCert(crt)
			continue
		}
		if isRootCA(crt) {
			pool.AddCert(crt)
			continue
		}
	}
	return pool, nil
}

func isIntermediateCertificate(c *x509.Certificate) bool {
	return c.IsCA && !bytes.Equal(c.RawIssuer, c.RawSubject)
}

func isRootCA(c *x509.Certificate) bool {
	return c.IsCA && bytes.Equal(c.RawIssuer, c.RawSubject)
}
