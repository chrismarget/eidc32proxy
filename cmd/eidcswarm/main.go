package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/chrismarget/eidc32proxy"
	"github.com/chrismarget/eidc32proxy/client"
)

const (
	defaultSiteKeyEnv = "EIDC_SITE_KEY"
)

func main() {
	intelliMRawURL := flag.String("u", "https://127.0.0.1:18800", "The URL to connect to")
	proxyRawURL := flag.String("proxy", "", "Optional proxy URL")
	siteKeyEnv := flag.String("site-key-env", defaultSiteKeyEnv,
		"Environment variable containing the site key\nA random site key is generated otherwise")
	optionalMACAddress := flag.String("mac", "",
		"Optional MAC address to use (defaults to random value for each client)")
	firmwareVersion := flag.String("firmware", "3.4.20", "The client's firmware version")
	numClients := flag.Int("n", 10, "Number of clients to simulate")
	showHelp := flag.Bool("h", false, "Display this help page")
	showExamples := flag.Bool("x", false, "Show example usages")

	flag.Parse()

	if *showHelp {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *showExamples {
		os.Stderr.WriteString(`[examples]

default usage:
client -u https://127.0.0.1:18800
`)
		os.Exit(1)
	}

	target, err := url.Parse(*intelliMRawURL)
	if err != nil {
		log.Fatalf("failed to parse target url - %s", err.Error())
	}

	var optionalProxy *url.URL
	if len(*proxyRawURL) > 0 {
		optionalProxy, err = url.Parse(*proxyRawURL)
		if err != nil {
			log.Fatalf("failed to parse proxy url - %s", err.Error())
		}
	}

	intellimURL := &client.IntellimURL{
		IntelliM:      target,
		OptionalProxy: optionalProxy,
	}

	sitekeys := make(map[string]struct{})
	optionalSiteKey, ok := os.LookupEnv(*siteKeyEnv)
	if !ok {
		for i := 0; i < *numClients; i++ {
			siteKey, err := client.RandomSiteKey()
			if err != nil {
				log.Fatalf("failed to generate a random site key - %s", err.Error())
			}
			_, ok := sitekeys[siteKey]
			if ok {
				i--
				continue
			}
			sitekeys[siteKey] = struct{}{}
		}
	}

	macsToSerials := make(map[string]string)
	var optionalSerial string
	if len(*optionalMACAddress) > 0 {
		optionalSerial, err = client.SerialNumberFromMACString(*optionalMACAddress)
		if err != nil {
			log.Fatalf("failed to generate serial number from specified mac - %s", err.Error())
		}
	} else {
		for i := 0; i < *numClients; i++ {
			mac, err := client.MostlyRandomMAC()
			if err != nil {
				log.Fatalf("failed to generate a random mac - %s", err.Error())
			}
			_, ok := macsToSerials[mac.String()]
			if ok {
				i--
				continue
			}
			macsToSerials[mac.String()] = client.SerialNumberFromMAC(mac.MAC)
		}
	}

	ips := make(map[string]struct{})
	for i := 0; i < *numClients; i++ {
		ip, err := client.RandomInternalIPv4Address()
		if err != nil {
			log.Fatalf("failed to generate a random ip address - %s", err.Error())
		}
		_, ok := ips[ip.String()]
		if ok {
			i--
			continue
		}
		ips[ip.String()] = struct{}{}
	}

	serverKeys := make(map[string]struct{})
	for i := 0; i < *numClients; i++ {
		serverKey, err := client.RandomServerKey()
		if err != nil {
			log.Fatalf("failed to generate a random server key - %s", err.Error())
		}
		_, ok := serverKeys[serverKey]
		if ok {
			i--
			continue
		}
		serverKeys[serverKey] = struct{}{}
	}

	var clients []*client.Client
	wg := &sync.WaitGroup{}
	for i := 0; i < *numClients; i++ {
		req := eidc32proxy.ConnectedRequest{
			CardFormat:      "short",
			FirmwareVersion: *firmwareVersion,
		}
		if len(optionalSiteKey) > 0 {
			req.SiteKey = optionalSiteKey
		} else {
			for k := range sitekeys {
				req.SiteKey = k
				delete(sitekeys, k)
				break
			}
		}
		if len(*optionalMACAddress) > 0 {
			req.MacAddress = *optionalMACAddress
			req.SerialNumber = optionalSerial
		} else {
			for k, v := range macsToSerials {
				req.MacAddress = k
				req.SerialNumber = v
				delete(macsToSerials, k)
				break
			}
		}
		for k := range ips {
			req.IPAddress = k
			delete(ips, k)
			break
		}
		var serverKey string
		for k := range serverKeys {
			serverKey = k
			delete(serverKeys, k)
			break
		}
		raw, _ := json.MarshalIndent(&req, "", "    ")
		log.Printf("connecting to %s with config: %s",
			intellimURL.ConnectTo().String(), raw)
		eidcClient, err := connectTo(client.ConnectionConfig{
			URL:               intellimURL,
			FirstWriteTimeout: 60 * time.Second,
			FirstReadTimeout:  60 * time.Second,
			ServerKey:         serverKey,
			Request:           req,
		}, wg)
		if err != nil {
			for _, c := range clients {
				c.Close()
			}
			log.Fatalf("failed to connect client - %s", err.Error())
		}
		clients = append(clients, eidcClient)
	}

	controlC := make(chan os.Signal, 1)
	signal.Notify(controlC, os.Interrupt, os.Kill)

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		allDone <- struct{}{}
	}()
	select {
	case <-allDone:
		log.Println("all connections ended")
	case <-controlC:
		for _, c := range clients {
			c.Close()
		}
	}
}

func connectTo(info client.ConnectionConfig, onExited *sync.WaitGroup) (*client.Client, error) {
	rawGobrResp, err := eidc32proxy.EIDCHTTPResponseBytes(&eidc32proxy.EIDCHTTPResponseData{
		StatusCode: http.StatusOK,
		WrapperBody: &eidc32proxy.EIDCSimpleResponse{
			Cmd:    eidc32proxy.GetoutboundResponseCmd,
			Result: true,
		},
		Body: &eidc32proxy.GetOutboundResponse{
			SiteKey:                info.Request.SiteKey,
			PrimaryHostAddress:     strings.Split(info.URL.IntelliM.Host, ":")[0],
			PrimaryPort:            18800,
			SecondaryHostAddress:   "52.200.49.37",
			SecondaryPort:          18800,
			PrimarySsl:             1,
			SecondarySsl:           1,
			RetryInterval:          1,
			MaxRandomRetryInterval: 60,
			Enabled:                1,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pre-compute response to gobr - %w", err)
	}

	// Create a pager before connecting and subscribe so we
	// do not miss any messages.
	info.Pager = eidc32proxy.NewMessagePager()
	anyMessages, stopAnyMessages := info.Pager.Subscribe(eidc32proxy.SubInfo{
		Category: eidc32proxy.SubMsgCatAny,
	})
	getOutboundRequests, stopGetOutboundsRequests := info.Pager.Subscribe(eidc32proxy.SubInfo{
		MsgTypes: []eidc32proxy.MsgType{eidc32proxy.MsgTypeGetoutboundRequest},
	})
	garbageRequests, garbageUnsubFns := client.SubscribeTo(info.Pager,
		eidc32proxy.MsgTypeHeartbeatRequest,
		eidc32proxy.MsgTypeResetEventsRequest,
		eidc32proxy.MsgTypeEnableEventsRequest,
		eidc32proxy.MsgTypeSetOutboundRequest,
		eidc32proxy.MsgTypeSetWebUserRequest)
	unsubAllPagerSubsFn := func() {
		stopAnyMessages()
		stopGetOutboundsRequests()
		for _, unsub := range garbageUnsubFns {
			unsub()
		}
	}

	eidcClient, err := client.ConnectWithConfig(info)
	if err != nil {
		unsubAllPagerSubsFn()
		return nil, fmt.Errorf("failed to connect to %s - %s",
			info.URL.ConnectTo().String(), err.Error())
	}

	onExited.Add(1)
	go func() {
		sendWrapperFn := func(raw []byte, msgType eidc32proxy.MsgType) error {
			log.Printf("[notice] automaically responding to '%s' with:\n%s",
				msgType.String(), raw)
			return eidcClient.SendRaw(raw)
		}

		respondTrueErrs := client.TrueDat(sendWrapperFn, garbageRequests...)

		for {
			select {
			case err := <-eidcClient.OnConnClosed():
				if err != nil && !strings.HasSuffix(err.Error(), ": use of closed network connection") {
					log.Printf("[fatal] connection ended - %s", err.Error())
				} else {
					log.Println("[done] socket closed")
				}
				unsubAllPagerSubsFn()
				eidcClient.Close()
				onExited.Done()
				return
			case msg := <-anyMessages:
				if msg.Direction() == eidc32proxy.Northbound {
					log.Printf("[outgoing message]\n'%s'", msg.OrigBytes())
				} else {
					log.Printf("[incoming message]\n'%s'", msg.OrigBytes())
				}
			case <-getOutboundRequests:
				log.Println("responding to gobr...")

				err = eidcClient.SendRaw(rawGobrResp)
				if err != nil {
					log.Printf("failed to send response to getOutboundRequest - %s", err.Error())
					continue
				}

				log.Printf("sent this response to gobr: '%s'", rawGobrResp)
			case err := <-respondTrueErrs:
				if err != nil {
					log.Printf("[warning] failed to automatically respond to a message - %s", err.Error())
				}
			}
		}
	}()

	return eidcClient, nil
}
