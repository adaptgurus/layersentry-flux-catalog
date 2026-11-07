package testgateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func writeNew(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	e := f.Close()
	if err != nil {
		return err
	}
	return e
}

// Bootstrap creates a NEW private TEST_ONLY PKI and a single client session.
// The CA signing key is ephemeral and is never persisted. Nothing is imported
// into system trust, active control planes, provider identities or node agents.
// Failure leaves a non-reusable partial root for investigation, never overwrites.
func Bootstrap(path string, c Config) error {
	if !c.TestOnly {
		return errors.New("TEST_ONLY acknowledgement required")
	}
	c.Schema = schema
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	c.Deployment = hex.EncodeToString(id)
	c.Expires = time.Now().UTC().Add(time.Hour)
	// Validate the complete static boundary before any key generation.
	c.ClientSHA256 = fmt.Sprintf("%064x", 1)
	c.UpstreamSHA256 = fmt.Sprintf("%064x", 2)
	c.GatewaySHA256 = fmt.Sprintf("%064x", 3)
	if err := c.validate(time.Now()); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("canonical absolute test root required")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	root, err := Open(path)
	if err != nil {
		return err
	}
	defer root.Close()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LayerSentry TEST_ONLY " + c.Deployment}, NotBefore: time.Now().Add(-time.Minute), NotAfter: c.Expires, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := writeNew(root, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	for i, name := range []string{"front", "backend", "gateway", "client"} {
		pub, leafKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		uri, _ := url.Parse("spiffe://layersentry-test/" + c.Deployment + "/" + name)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "LayerSentry TEST_ONLY " + name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri}}
		if name == "front" || name == "backend" {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
		if err != nil {
			return err
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(leafKey)
		if err != nil {
			return err
		}
		if err := writeNew(root, name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		if err := writeNew(root, name+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})); err != nil {
			return err
		}
		switch name {
		case "backend":
			c.UpstreamSHA256 = fingerprint(der)
		case "gateway":
			c.GatewaySHA256 = fingerprint(der)
		case "client":
			c.ClientSHA256 = fingerprint(der)
		}
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	if err := writeNew(root, "gateway.token", []byte(hex.EncodeToString(token))); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(root, "config.json", append(b, '\n')); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
