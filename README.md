# Go DTLS sample with the Pion library

This is a Go sample that uses the [Pion library]() for DTLS.

## Client certificate and private key

The sample code reads the certificate and private key from the files `cert.crt` and `key.pem`. Both files must be PEM-encoded. The `cert.crt` contains the client certificate, intermediates and root and the `key.pem` file contains the private key.

Use the [span CLI](https://github.com/lab5e/spancli) to generate a certificate and key file.

