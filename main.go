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

// The version is set by go build (-ldflags "-X main.Version=x.x.x")
var Version = "0.0.0"

const (
	host     = "data.lab5e.com"
	port     = 1234
	certFile = "cert.crt"
	keyFile  = "key.pem"
)

func main() {
	fmt.Printf("Version %s\n", Version)
	// Read the certificate file with the client certificate and intermediates
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Printf("Error reading cert file: %v\n", err)
		os.Exit(1)
	}

	// Read the private key file./d
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("Error reading key file: %v\n", err)
		os.Exit(1)
	}

	// Build a client certificate with the client certificate and private key. The resulting
	// certificate structure will just contain the client certificate
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		fmt.Printf("Could not create key pair: %v\n", err)
		os.Exit(1)
	}

	// Create certificate pool with the remaining certifiates.
	intermediates, roots, err := loadCertPool(certBytes)
	if err != nil {
		fmt.Printf("Error loading certificate pool: %v\n", err)
		os.Exit(1)
	}

	// Set up the TLS config for the connection. Ideally
	tlsConfig := &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		RootCAs:            roots,
		ClientCAs:          intermediates,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 30*time.Second)
		},
	}

	// Set up a context for the DTLS connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ipaddrs, err := net.LookupIP(host)
	if err != nil {
		fmt.Printf("Error resolving host name: %v\n", err)
		os.Exit(1)
	}
	// Resolve the host
	addr := &net.UDPAddr{IP: ipaddrs[0], Port: port}

	// Dial the server
	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, tlsConfig)
	if err != nil {
		fmt.Printf("Error dialing server: %v\n", err)
		os.Exit(1)
	}

	defer dtlsConn.Close()

	payload := []byte("This Is A Go Sample Message")

	// Send the payload to the server
	_ = dtlsConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err = dtlsConn.Write(payload)
	if err != nil {
		fmt.Printf("Error writing DTLS packet: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent %d bytes to service\n", len(payload))

	// Check if there's a response by setting the read deadline and attempting a read.
	_ = dtlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _ := dtlsConn.Read(payload)
	if n > 0 {
		fmt.Printf("Got %d bytes from service\n", n)
	}
}

// loadCertPool parses and loads certificates from a byte buffer into two pools;
// one for intermediates and one for root certificates.
func loadCertPool(pemBytes []byte) (*x509.CertPool, *x509.CertPool, error) {
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
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for _, crt := range certs {
		if isIntermediateCertificate(crt) {
			intermediates.AddCert(crt)
			continue
		}
		if isRootCA(crt) {
			roots.AddCert(crt)
			continue
		}
	}
	return intermediates, roots, nil
}

// Intermediate certificates can sign new certificates (the IsCA flag is set) but the
// issuer is different from the certificate
func isIntermediateCertificate(c *x509.Certificate) bool {
	return c.IsCA && !bytes.Equal(c.RawIssuer, c.RawSubject)
}

// Root CAs have the same issuer and subject fields
func isRootCA(c *x509.Certificate) bool {
	return c.IsCA && bytes.Equal(c.RawIssuer, c.RawSubject)
}
