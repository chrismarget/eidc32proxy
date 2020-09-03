package eidc32proxy

/* connect from the "bridge" host with:
LD_LIBRARY_PATH=/opt/openssl-1.1.1/lib/:$LD_LIBRARY_PATH openssl s_client -cipher  'RC4-MD5:@SECLEVEL=0' -connect 192.168.15.46:18800
*/

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/chrismarget/terribletls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	network       = "tcp4"
	errConnClosed = "use of closed network connection"
	keyLogFile    = ".eidc32proxy.keys"
)

type Server struct {
	tlsConfig   *terribletls.Config
	nl          net.Listener
	stop        chan struct{}
	sessions    map[int]*Session
	err         chan error
	sessChMap   map[chan *Session]struct{}
	sessChMutex *sync.Mutex
}

// NewServer returns an eidc32proxy Server object. It takes the TLS details as
// input. Typical usage involves listening for errors by calling ErrChan()
// (once), and subscribing to session creation info with SubscribeSessions()
// (many listeners okay), then starting it up with Serve().
// If x509Cert or privkey are nil, the server will not do SSL.
func NewServer(x509Cert *x509.Certificate, privkey *rsa.PrivateKey, optionalDERCertChain [][]byte) (Server, error) {
	var tlsConfig *terribletls.Config

	if x509Cert != nil && privkey != nil {
		keyLog, err := keyLogWriter()
		if err != nil {
			return Server{}, err
		}

		certBlock := bytes.NewBuffer(nil)
		err = pem.Encode(certBlock, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x509Cert.Raw,
		})
		if err != nil {
			return Server{}, fmt.Errorf("failed to pem encode certificate block - %w", err)
		}

		privateKeyBlock := bytes.NewBuffer(nil)
		err = pem.Encode(privateKeyBlock, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		})
		if err != nil {
			return Server{}, fmt.Errorf("failed to pem encode private key block - %w", err)
		}

		tlsCert, err := terribletls.X509KeyPair(certBlock.Bytes(), privateKeyBlock.Bytes())
		if err != nil {
			return Server{}, err
		}

		if len(optionalDERCertChain) > 0 {
			tlsCert.Certificate = append(tlsCert.Certificate, optionalDERCertChain...)
		}

		tlsConfig = &terribletls.Config{
			KeyLogWriter:                keyLog,
			Rand:                        rand.Reader,
			Certificates:                []terribletls.Certificate{tlsCert},
			CipherSuites:                []uint16{terribletls.TLS_RSA_WITH_RC4_128_MD5},
			PreferServerCipherSuites:    true,
			SessionTicketsDisabled:      true,
			MinVersion:                  terribletls.VersionTLS10,
			MaxVersion:                  terribletls.VersionTLS12,
			DynamicRecordSizingDisabled: true,
		}
	}

	return Server{
		err:         make(chan error),
		stop:        make(chan struct{}),
		sessions:    make(map[int]*Session),
		sessChMap:   make(map[chan *Session]struct{}),
		sessChMutex: &sync.Mutex{},
		tlsConfig:   tlsConfig,
	}, nil
}

// Serve loops forever handing off new connections to initSession().
// It returns an error if there's a problem prior to starting the client
// handling loop. Any errors encountered in the client handling loop
// are returned on the server's "Err" channel.
func (o Server) Serve(port int) error {
	var nl net.Listener
	var err error

	laddr := ":" + strconv.Itoa(port)
	if o.tlsConfig != nil {
		nl, err = terribletls.Listen(network, laddr, o.tlsConfig)
	} else {
		nl, err = net.Listen(network, laddr)
	}
	if err != nil {
		return err
	}

	// loop accepting incoming connections
	go o.serve(nl)

	// this should stop everything. does it? no idea.
	go func() {
		<-o.stop
		nl.Close()
		close(o.stop)
		close(o.err)
	}()

	return nil
}

func keyLogWriter() (io.Writer, error) {
	keyLogDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	keyLogFile := filepath.Join(keyLogDir, keyLogFile)

	err = os.MkdirAll(filepath.Dir(keyLogFile), os.FileMode(0644))
	if err != nil {
		return nil, err
	}

	return os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
}

func (o *Server) serve(nl net.Listener) {
	defer o.unsubEverybody()
	// loop forever accepting new connections
	var sessionID int
	for {
		conn, err := nl.Accept()
		if err != nil {
			if strings.HasSuffix(err.Error(), errConnClosed) {
				o.err <- err
				return
			}
			o.err <- err
			continue
		}

		// connection accepted, init session
		go func(id int) {
			//session, err := newSession(id, conn, o.eventInChan)
			session, err := newSession(conn)
			if err != nil {
				o.err <- err
				return
			}

			// announce the session to all interested channels
			o.sessChMutex.Lock()
			for c := range o.sessChMap {
				c <- session
			}
			o.sessChMutex.Unlock()

		}(sessionID)
		sessionID++
	}
}

func (o *Server) unsubEverybody() {
	o.sessChMutex.Lock()
	for c := range o.sessChMap {
		close(c)
		delete(o.sessChMap, c)
	}
	o.sessChMutex.Unlock()
}

// Stop stops the server by writing to the stop channel
func (o *Server) Stop() {
	o.stop <- struct{}{}
}

// Errors returns the server's error channel
func (o *Server) ErrChan() chan error {
	return o.err
}

// SubscribeSessions returns a new Session channel. New sessions will
// be written to the channel as they establish connections.
func (o *Server) SubscribeSessions() chan *Session {
	c := make(chan *Session)
	o.sessChMutex.Lock()
	o.sessChMap[c] = struct{}{}
	o.sessChMutex.Unlock()
	return c
}

// UnSubscribeSessions allows a subscriber remove its channel from the
// new session interest list by submitting it to this function.
func (o *Server) UnSubscribeSessions(c chan *Session) {
	o.sessChMutex.Lock()
	delete(o.sessChMap, c)
	o.sessChMutex.Unlock()
}
