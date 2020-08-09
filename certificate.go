package eidc32proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

const (
	pemPKCS1           = "RSA PRIVATE KEY"
	pemCertificateType = "CERTIFICATE"
)

// CertSetup contains details required for creating a self-signed certificate
type CertSetup struct {
	certFile   string
	keyFile    string
	passphrase string
	bits       int
	template   *x509.Certificate
}

// InfiniasCertSetup returns certificate generation parameters required
// to generate a certificate like one offered by a "real" cloud server.
// For example:
// -----BEGIN CERTIFICATE-----
//MIICjTCCAfagAwIBAgIQbF0wWR4jxZlEeXF9ZQrTQTANBgkqhkiG9w0BAQUFADCB
//hDEUMBIGA1UEAxMLM3hMT0dJQyBJbmMxETAPBgNVBAoTCGluZmluaWFzMRUwEwYD
//VQQHEwxJbmRpYW5hcG9saXMxEDAOBgNVBAgTB0luZGlhbmExCzAJBgNVBAYTAlVT
//MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGluZmluaWFzLmNvbTAeFw0xOTExMDgw
//NDU5MjRaFw0yNDExMDYwNDU5MjRaMIGEMRQwEgYDVQQDEwszeExPR0lDIEluYzER
//MA8GA1UEChMIaW5maW5pYXMxFTATBgNVBAcTDEluZGlhbmFwb2xpczEQMA4GA1UE
//CBMHSW5kaWFuYTELMAkGA1UEBhMCVVMxIzAhBgkqhkiG9w0BCQEWFHN1cHBvcnRA
//aW5maW5pYXMuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9VGrhQAjO
//lEgODdgthV/6c8YSSu6VkMSeke8326gaxRxgahr6Hx4HcVKuc6sXxtlZSeCZ/FQW
//ZJ7/Tcg7t8cIl7vCriReK6gaGiylPflSfK0kHFO682DM8Q4Kk9XPfmG7owImAYfJ
//ScCSegytHF1W3vxwdakEuvEq5wxQcuFebwIDAQABMA0GCSqGSIb3DQEBBQUAA4GB
//AJ150Lc8BqGua8XA7sq5TedxgoVlyP1lMCKwpuQCVf7CR4/Z19cqxixIQ4vV1//+
//ibu/dqr4e6wcRHjpMzS/yZaC6ShLiPZHCmcLApn5xD+f30GxAN76LKFo+2ua6REU
//e7CTWdoQQ3Q/d99HPXOPCOxNNP0utDPI62GHV8pBEB0O
//-----END CERTIFICATE-----
func InfiniasCertSetup() *CertSetup {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}

	subject := pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: []int{2, 5, 4, 3},
				Value: "3xLOGIC Inc"},
			{Type: []int{2, 5, 4, 10},
				Value: "infinias"},
			{Type: []int{2, 5, 4, 7},
				Value: "Indianapolis"},
			{Type: []int{2, 5, 4, 8},
				Value: "Indiana"},
			{Type: []int{2, 5, 4, 6},
				Value: "US"},
			{Type: []int{1, 2, 840, 113549, 1, 9, 1},
				Value: "support@infinias.com"},
		},
	}

	return &CertSetup{
		certFile:   "",
		keyFile:    "",
		passphrase: "",
		bits:       1024,
		template: &x509.Certificate{
			SerialNumber:       serialNumber,
			SignatureAlgorithm: x509.SHA1WithRSA,
			Subject:            subject,
			Issuer:             subject,
			NotBefore:          time.Now().Add(time.Duration(-86400) * time.Second),
			NotAfter:           time.Now().Add(time.Duration(1824*86400) * time.Second),
		},
	}
}

// readPemFile reads a file, returns a pointer
// to the PEM block found within.
// todo: not directly tested
func readPemFile(fname string) (*pem.Block, error) {
	fileBytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(fileBytes)
	if p == nil {
		return nil, fmt.Errorf("failed to parse PEM file %s", fname)
	}

	return p, nil
}

// getGeyFromFile reads an RSA key file in PEM format, returns a pointer to the
// key found within. The file must begin "-----BEGIN RSA PRIVATE KEY-----"
// (PKCS#1 format). PKCS#8 files ("BEGIN PRIVATE KEY") are not supported. If
// 'pass' is not empty, the function will attempt to decrypt the key using the
// supplied passphrase.
func getKeyFromFile(fname string, pass string) (*rsa.PrivateKey, error) {
	p, err := readPemFile(fname)
	if err != nil {
		return nil, err
	}

	if p.Type != pemPKCS1 {
		return nil, fmt.Errorf("%s unrecognized PEM file type: %s", fname, p.Type)
	}

	var decryptedKeyBytes []byte
	if pass != "" {
		decryptedKeyBytes, err = x509.DecryptPEMBlock(p, []byte(pass))
		if err != nil {
			return nil, err
		}
	} else {
		decryptedKeyBytes = p.Bytes
	}

	return x509.ParsePKCS1PrivateKey(decryptedKeyBytes)
}

// getCertFromFile parses a PEM formatted certificate file, returns
// a pointer to the certificate found within.
func getCertFromFile(fname string) (*x509.Certificate, error) {
	p, err := readPemFile(fname)
	if err != nil {
		return nil, err
	}

	if p.Type != pemCertificateType {
		return nil, fmt.Errorf("file %s not a certificate", fname)
	}

	return x509.ParseCertificate(p.Bytes)
}

// getOrGenKey returns a pointer to an RSA private key. Whether it retrieves
// a key or generates a key depends on whether keyFile is empty. The passphrase
// string must not be empty if retrieving an encrypted key. Int bits is ignored
// when retrieving a key.
func getOrGenKey(keyFile string, passphrase string, bits int) (*rsa.PrivateKey, error) {
	if keyFile != "" {
		return getKeyFromFile(keyFile, passphrase)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// getOrGenCert returns a pointer to an x509.Certificate. If certFile is not
// empty, it will try to return the certificate the specified file. In that
// case the other parameters are ignored. If certFile is empty, then key and
// template are required. They're used to generate a self-signed certificate.
// todo: not directly tested
func getOrGenCert(certFile string, key crypto.Signer, template *x509.Certificate) (*x509.Certificate, error) {
	if certFile != "" {
		return getCertFromFile(certFile)
	}

	if template == nil {
		return nil, errors.New("neither certificate nor cert template provided")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		log.Println("oops")
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

// CertAndKey generates or retrieves a key and certificate, depending on what's
// in the specified CertSetup. It can retrieve both, retrieve a key and generate
// a certificate, or generate both a certificate and a key.
func CertAndKey(in *CertSetup) (*x509.Certificate, *rsa.PrivateKey, error) {
	if in.passphrase != "" && in.keyFile == "" {
		return nil, nil, fmt.Errorf("key file unspecified but passphrase specified")
	}

	if in.certFile != "" && in.keyFile == "" {
		return nil, nil, fmt.Errorf("key file unspecified but certfile specified")
	}

	key, err := getOrGenKey(in.keyFile, in.passphrase, in.bits)
	if err != nil {
		return nil, nil, err
	}

	cert, err := getOrGenCert(in.certFile, key, in.template)
	if err != nil {
		return nil, nil, err
	}

	certPubKey := cert.PublicKey.(*rsa.PublicKey)
	keyPubKey := key.PublicKey
	if certPubKey.Size() != keyPubKey.Size() || certPubKey.E != keyPubKey.E {
		return nil, nil, fmt.Errorf("certificate and key don't match")
	}
	if certPubKey.N.Cmp(keyPubKey.N) != 0 {
		return nil, nil, fmt.Errorf("certificate and key don't match")
	}

	return cert, key, nil
}
