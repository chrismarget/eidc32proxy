package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"github.com/chrismarget/eidc32proxy"
	"github.com/chrismarget/eidc32proxy/display"
	"log"
	"os"
	"os/signal"
	"time"
)

const (
	sslPort   = 18800
	clearPort = 18880
	progName  = "eidc32proxy"
	version   = "0.9"
)

const (
	displayTview displayType = iota
	displayDump
	displayLog
)

type displayType int

type config struct {
	display       displayType
	mimicCert     string
	mimicCertEvil string
	useCert       string
	usePrivateKey string
}

func getConfig() *config {
	dtype := flag.String("d", "", "display type: dumpfirst/log/tview (default tview)")
	mimicCert := flag.String("m", "", "mimic the specified end-entity X.509 certificate")
	mimicCertEvil := flag.String("me", "", "mimic the specified end-entity cert in an evil way")
	useCert := flag.String("c", "", "use the PEM-encoded X.509 certificate at the specified path")
	usePrivateKey := flag.String("k", "", "use the PEM-encoded privtate key at the specified path")
	flag.Parse()
	config := &config{
		mimicCert:     *mimicCert,
		mimicCertEvil: *mimicCertEvil,
		useCert:       *useCert,
		usePrivateKey: *usePrivateKey,
	}
	switch *dtype {
	case "tview":
		config.display = displayTview
	case "dump":
		config.display = displayDump
	case "log":
		config.display = displayLog
	}
	return config
}

/* talk to this thing with:
LD_LIBRARY_PATH=/opt/openssl-1.1.1/lib/:$LD_LIBRARY_PATH openssl s_client -cipher  'RC4-MD5:@SECLEVEL=0' -connect 192.168.15.46:18800 -ign_eof
*/

func main() {
	config := getConfig()

	var cert *x509.Certificate
	var key *rsa.PrivateKey
	var err error
	if len(config.usePrivateKey) > 0 {
		log.Printf("using private key at '%s'...", config.usePrivateKey)
		pb, err := eidc32proxy.PEMDecodeFirstItem(config.usePrivateKey)
		if err != nil {
			log.Fatalf("failed to pem decode - %s", err)
		}
		k, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
		if err != nil {
			log.Fatalf("failed to parse private key - %s", err)
		}
		var ok bool
		if key, ok = k.(*rsa.PrivateKey); !ok {
			log.Fatalf("key is not a rsa key")
		}
	}
	if len(config.useCert) > 0 {
		log.Printf("using certificate at '%s'...", config.useCert)
		pb, err := eidc32proxy.PEMDecodeFirstItem(config.useCert)
		if err != nil {
			log.Fatalf("failed to pem decode - %s", err)
		}
		cert, err = x509.ParseCertificate(pb.Bytes)
		if err != nil {
			log.Fatalf("failed to parse certificate - %s", err)
		}
	}
	if len(config.mimicCert) > 0 {
		log.Printf("mimicking certificate at '%s'...", config.mimicCert)
		_, mimickedEE, err := eidc32proxy.MimicCertFromFile(config.mimicCert)
		if err != nil {
			log.Fatalf("failed to mimic cert - %s", err)
		}
		cert = mimickedEE.Cert
		var ok bool
		key, ok = mimickedEE.KeyPair.PrivKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatalf("this code currently only supports rsa private keys, mimic created %t",
				mimickedEE.KeyPair.PrivKey)
		}
	} else if len(config.mimicCertEvil) > 0 {
		log.Printf("mimicking (in an evil way) certificate at '%s'...", config.mimicCertEvil)
		mimickedEE, err := eidc32proxy.MimicCertNoWayAnyoneWouldBelieveThisFromPEMFile(config.mimicCertEvil)
		if err != nil {
			log.Fatalf("failed to mimic cert - %s", err)
		}
		cert = mimickedEE.Cert
		var ok bool
		key, ok = mimickedEE.KeyPair.PrivKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatalf("this code currently only supports rsa private keys, mimic created %t",
				mimickedEE.KeyPair.PrivKey)
		}
	} else {
		log.Println("generating new cert and key...")
		// prepare TLS certificate and key we'll present to eIDC32 clients
		cert, key, err = eidc32proxy.CertAndKey(eidc32proxy.InfiniasCertSetup())
	}
	if err != nil {
		log.Fatal(err)
	}

	// create a new SSL server using that cert and key
	sslServer, err := eidc32proxy.NewServer(cert, key)
	if err != nil {
		log.Fatal(err)
	}

	// create a new cleartext server
	clearServer, err := eidc32proxy.NewServer(nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	// start the sslServer
	err = sslServer.Serve(sslPort)
	if err != nil {
		log.Fatal(err)
	}

	// start the clearServer
	err = clearServer.Serve(clearPort)
	if err != nil {
		log.Fatal(err)
	}

	controlC := make(chan os.Signal)
	signal.Notify(controlC, os.Interrupt, os.Kill)

	// Aggregate the all server instance session channels into a single channel
	sessAgg := func(in, out chan *eidc32proxy.Session) {
		for newSess := range in {
			out <- newSess
		}
	}
	aggregatedSessions := make(chan *eidc32proxy.Session)           // The aggregate channel
	go sessAgg(sslServer.SubscribeSessions(), aggregatedSessions)   // Aggregate ssl sessions
	go sessAgg(clearServer.SubscribeSessions(), aggregatedSessions) // Aggregate clear sessions

	var disp display.Display

	switch config.display {
	case displayTview:
		disp = display.NewTVDisplay(aggregatedSessions)
	case displayDump:
		disp = display.NewDumpFirstDisplay(aggregatedSessions)
	}

	go disp.Run()

MAINLOOP:
	for {
		select {
		case <-controlC: // Stop channel says stop
			break MAINLOOP
		case err := <-sslServer.ErrChan(): // sslServer produced an error
			log.Println("SSL server Error:", err.Error())
			break MAINLOOP
		case err := <-clearServer.ErrChan(): // clearServer produced an error
			log.Println("Cleartext server Error:", err.Error())
			break MAINLOOP
		case err := <-disp.ErrChan(): // display produced an error
			if err != nil {
				log.Println("Display Error:", err.Error())
			}
			break MAINLOOP
		}
	}
	sslServer.Stop()
	clearServer.Stop()
}

func injectExample(s *eidc32proxy.Session) {
	time.Sleep(60 * time.Second)
	msgToInject, err := eidc32proxy.NewHeartbeatMsg("admin", "admin")
	if err != nil {
		log.Println("inject error: ", err.Error())
	}
	mangler := eidc32proxy.DropMessageByType{
		DropType:  eidc32proxy.MsgTypeHeartbeatResponse,
		Remaining: 1,
	}
	s.Inject(*msgToInject, []eidc32proxy.Mangler{&mangler})
}
