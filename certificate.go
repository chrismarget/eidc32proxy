package eidc32proxy

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	CertFile   string
	KeyFile    string
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
		CertFile:   "",
		KeyFile:    "",
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

// GetCertFromFile parses a PEM formatted certificate file, returns
// a pointer to the certificate found within.
func GetCertFromFile(fname string) (*x509.Certificate, error) {
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
// a key or generates a key depends on whether KeyFile is empty. The passphrase
// string must not be empty if retrieving an encrypted key. Int bits is ignored
// when retrieving a key.
func getOrGenKey(keyFile string, passphrase string, bits int) (*rsa.PrivateKey, error) {
	if keyFile != "" {
		return getKeyFromFile(keyFile, passphrase)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// getOrGenCert returns a pointer to an x509.Certificate. If CertFile is not
// empty, it will try to return the certificate the specified file. In that
// case the other parameters are ignored. If CertFile is empty, then key and
// template are required. They're used to generate a self-signed certificate.
// todo: not directly tested
func getOrGenCert(certFile string, key crypto.Signer, template *x509.Certificate) (*x509.Certificate, error) {
	if certFile != "" {
		return GetCertFromFile(certFile)
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
	if in.passphrase != "" && in.KeyFile == "" {
		return nil, nil, fmt.Errorf("key file unspecified but passphrase specified")
	}

	if in.CertFile != "" && in.KeyFile == "" {
		return nil, nil, fmt.Errorf("key file unspecified but certfile specified")
	}

	key, err := getOrGenKey(in.KeyFile, in.passphrase, in.bits)
	if err != nil {
		return nil, nil, err
	}

	cert, err := getOrGenCert(in.CertFile, key, in.template)
	if err != nil {
		return nil, nil, err
	}

	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("failed to type assert generated public key as rsa")
	}
	keyPubKey := key.PublicKey
	if certPubKey.Size() != keyPubKey.Size() || certPubKey.E != keyPubKey.E {
		return nil, nil, fmt.Errorf("certificate and key don't match")
	}
	if certPubKey.N.Cmp(keyPubKey.N) != 0 {
		return nil, nil, fmt.Errorf("certificate and key don't match")
	}

	return cert, key, nil
}

func pemToCert(rawPEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(rawPEM)
	if len(rest) > 0 {
		return nil, fmt.Errorf("only a single pem block is supported - pem contains %d blocks", len(rest))
	}

	return x509.ParseCertificate(block.Bytes)
}

func MimicCertNoWayAnyoneWouldBelieveThisFromPEMFile(certFilePath string) (*CertificateHolder, error) {
	cert, err := GetCertFromFile(certFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from file - %w", err)
	}

	return MimicCertNoWayAnyoneWouldBelieveThis(cert)
}

func MimicCertNoWayAnyoneWouldBelieveThis(orig *x509.Certificate) (*CertificateHolder, error) {
	_, ee, err := MimicCert(orig)
	if err != nil {
		return nil, err
	}

	eePEMBlock, _ := pem.Decode(ee.CertPEM)
	if eePEMBlock == nil {
		return nil, fmt.Errorf("failed to pem decode new end entity cert - %s", err)
	}

	i := bytes.Index(eePEMBlock.Bytes, ee.Cert.Signature)
	if i < 0 {
		return nil, fmt.Errorf("failed to find new end entity cert signature in der data")
	}

	finalDer := append(eePEMBlock.Bytes[:i], orig.Signature...)
	finalDer = append(finalDer, eePEMBlock.Bytes[i+len(ee.Cert.Signature):]...)

	finalPEM := bytes.NewBuffer(nil)
	err = pem.Encode(finalPEM, &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   finalDer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pem encode butchered cert - %s", err)
	}

	tlsCert, err := tls.X509KeyPair(finalPEM.Bytes(), ee.KeyPair.PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to regenerate tls cert - %w", err)
	}

	eeCert, err := x509.ParseCertificate(finalDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse butchered ee cert - %w", err)
	}

	return &CertificateHolder{
		TLSCert: &tlsCert,
		Cert:    eeCert,
		CertPEM: finalPEM.Bytes(),
		CertDER: finalDer,
		KeyPair: ee.KeyPair,
	}, nil
}

// MimicCert attempts to mimic the PEM-encoded X.509 certificate found at the
// specified file path.
func MimicCertFromFile(certFilePath string) (parent *CertificateHolder, endEntity *CertificateHolder, err error) {
	cert, err := GetCertFromFile(certFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get certificate from file - %w", err)
	}

	return MimicCert(cert)
}

// MimicCert attempts to mimic the provided X.509 certificate.
func MimicCert(orig *x509.Certificate) (parent *CertificateHolder, endEntity *CertificateHolder, err error) {
	eeKP, err := MimicKeyPairForPublicKey(orig.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to mimic key pair for cert's public key - %w", err)
	}

	mimickedEE := certToTemplate(orig)
	var finalParent *x509.Certificate
	var signWith interface{}
	if orig.Issuer.String() != orig.Subject.String() {
		parent, err = mimicParentCert(orig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to mimic cert's parent - %w", err)
		}
		finalParent = parent.Cert
		signWith = parent.KeyPair.PrivKey
	} else {
		finalParent = mimickedEE
		signWith = eeKP.PrivKey
	}

	endEntity, err = newCertificate(mimickedEE, finalParent, eeKP, signWith)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate end entity certificate - %w", err)
	}

	if parent == nil {
		parent = endEntity
	}

	return
}

func mimicParentCert(child *x509.Certificate) (*CertificateHolder, error) {
	kp, err := MimicKeyPairForPublicKey(child.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a new key pair - %w", err)
	}

	temp := certToTemplate(child)

	temp.Subject = child.Issuer
	newSN := *temp.SerialNumber
	snRaw := newSN.Bytes()
	lastByte := snRaw[len(snRaw)-1]
	lastByte--
	snRaw[len(snRaw)-1] = lastByte
	temp.SerialNumber = &newSN
	temp.NotBefore = child.NotBefore.Add(-(365 * (24 * time.Hour)))
	temp.NotAfter = child.NotAfter.Add(365 * (24 * time.Hour))
	temp.BasicConstraintsValid = true
	temp.IsCA = true
	temp.DNSNames = nil
	temp.IPAddresses = nil
	temp.KeyUsage = child.KeyUsage | x509.KeyUsageCertSign

	// The following is a massive super-hack that works around
	// 'x509.Certificate.ExtraExtensions' overriding key usages
	// and other X.509 extension.
	originalExtensions := temp.ExtraExtensions
	temp.ExtraExtensions = nil
	finalDER, err := x509.CreateCertificate(rand.Reader, temp, temp, kp.PubKey, kp.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to re-create certificate - %w", err)
	}
	final, err := x509.ParseCertificate(finalDER)
	if err != nil {
		return nil, fmt.Errorf("failed to re-parse certificate - %w", err)
	}

	final = certToTemplate(final)

	var additionalExts []pkix.Extension
	keyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 15}
	basicConstraintsValidOID := asn1.ObjectIdentifier{2, 5, 29, 19}
	for _, ext := range originalExtensions {
		switch ext.Id.String() {
		case keyUsageOID.String():
			continue
		case basicConstraintsValidOID.String():
			continue
		}
		additionalExts = append(additionalExts, ext)
	}

	final.ExtraExtensions = append(final.ExtraExtensions, additionalExts...)

	return newCertificate(final, final, kp, kp.PrivKey)
}

// TODO: Garbage.
func similarSerialNumber(orig *big.Int) (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), uint(orig.BitLen()))
	sn, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number - %s", err.Error())
	}

	// If the first byte is greater than 127, then we have the wrong bits.
	if sn.Bytes()[0] > 127 {
		return similarSerialNumber(orig)
	}

	return sn, nil
}

func MimicKeyPairForPublicKey(origPublicKey interface{}) (*KeyPair, error) {
	var privF interface{}
	var pubF interface{}
	var pemLabel string

	switch asserted := origPublicKey.(type) {
	case *dsa.PublicKey:
		return nil, fmt.Errorf("dsa is not supported at this time (good)")
	case *ecdsa.PublicKey:
		priv, err := ecdsa.GenerateKey(asserted.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new ecdssa private key - %w", err)
		}
		privF = priv
		pubF = &priv.PublicKey
		pemLabel = "EC PRIVATE KEY"
	case *ed25519.PublicKey:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new ed25519 private key - %w", err)
		}
		privF = priv
		pubF = pub
		pemLabel = "ED25519 PRIVATE KEY"
	case *rsa.PublicKey:
		priv, err := rsa.GenerateKey(rand.Reader, asserted.N.BitLen())
		if err != nil {
			return nil, fmt.Errorf("failed to generate new rsa private key - %w", err)
		}
		privF = priv
		pubF = &priv.PublicKey
		pemLabel = "RSA PRIVATE KEY"
	default:
		return nil, fmt.Errorf("unknown public key type %T", origPublicKey)
	}

	keyDer, err := x509.MarshalPKCS8PrivateKey(privF)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to der - %w", err)
	}

	pemBuff := bytes.NewBuffer(nil)
	err = pem.Encode(pemBuff, &pem.Block{
		Type:    pemLabel,
		Headers: nil,
		Bytes:   keyDer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pem encode prviate key - %w", err)
	}

	return &KeyPair{
		PEMLabel: pemLabel,
		PEM:      pemBuff.Bytes(),
		PubKey:   pubF,
		PrivKey:  privF,
	}, nil
}

type KeyPair struct {
	PEMLabel string
	PEM      []byte
	PubKey   interface{}
	PrivKey  interface{}
}

func certToTemplate(orig *x509.Certificate) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:                orig.SerialNumber,
		SignatureAlgorithm:          orig.SignatureAlgorithm,
		Subject:                     orig.Subject,
		NotBefore:                   orig.NotBefore,
		NotAfter:                    orig.NotAfter,
		KeyUsage:                    orig.KeyUsage,
		ExtraExtensions:             orig.Extensions,
		ExtKeyUsage:                 orig.ExtKeyUsage,
		UnknownExtKeyUsage:          orig.UnknownExtKeyUsage,
		BasicConstraintsValid:       orig.BasicConstraintsValid,
		IsCA:                        orig.IsCA,
		MaxPathLen:                  orig.MaxPathLen,
		MaxPathLenZero:              orig.MaxPathLenZero,
		SubjectKeyId:                orig.SubjectKeyId,
		AuthorityKeyId:              orig.AuthorityKeyId,
		OCSPServer:                  orig.OCSPServer,
		IssuingCertificateURL:       orig.IssuingCertificateURL,
		DNSNames:                    orig.DNSNames,
		EmailAddresses:              orig.EmailAddresses,
		IPAddresses:                 orig.IPAddresses,
		URIs:                        orig.URIs,
		PermittedDNSDomainsCritical: orig.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         orig.PermittedDNSDomains,
		ExcludedDNSDomains:          orig.ExcludedDNSDomains,
		PermittedIPRanges:           orig.PermittedIPRanges,
		ExcludedIPRanges:            orig.ExcludedIPRanges,
		PermittedEmailAddresses:     orig.PermittedEmailAddresses,
		ExcludedEmailAddresses:      orig.ExcludedEmailAddresses,
		PermittedURIDomains:         orig.PermittedURIDomains,
		ExcludedURIDomains:          orig.ExcludedURIDomains,
		CRLDistributionPoints:       orig.CRLDistributionPoints,
		PolicyIdentifiers:           orig.PolicyIdentifiers,
	}
}

func newCertificate(eeTemplate *x509.Certificate, parent *x509.Certificate, kp *KeyPair, signWith interface{}) (*CertificateHolder, error) {
	newCertDER, err := x509.CreateCertificate(rand.Reader, eeTemplate, parent, kp.PubKey, signWith)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert - %w", err)
	}

	x509CertWithPopulatedFields, err := x509.ParseCertificate(newCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to re-parse new cert der - %w", err)
	}

	newCertPEM := bytes.NewBuffer(nil)
	err = pem.Encode(newCertPEM, &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   newCertDER,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pem encode new cert - %w", err)
	}

	newTLSCert, err := tls.X509KeyPair(newCertPEM.Bytes(), kp.PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert and private key as tls cert - %w", err)
	}

	return &CertificateHolder{
		TLSCert: &newTLSCert,
		Cert:    x509CertWithPopulatedFields,
		CertPEM: newCertPEM.Bytes(),
		CertDER: newCertDER,
		KeyPair: kp,
	}, nil
}

type CertificateHolder struct {
	TLSCert *tls.Certificate
	Cert    *x509.Certificate
	CertPEM []byte
	CertDER []byte
	KeyPair *KeyPair
}

func PEMDecodeFirstItem(filePath string) (*pem.Block, error) {
	raw, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no pem data present")
	}

	return block, nil
}
