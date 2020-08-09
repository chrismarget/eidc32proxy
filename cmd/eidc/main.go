package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
	siteKeyEnv := flag.String("site-key-env", defaultSiteKeyEnv, "Environment variable containing the site key")
	allowEmptySiteKey := flag.Bool("allow-empty-site-key", false, "Allow an empty site")
	serverKey := flag.String("server-key", "", "The initial server key to use (defaults to random string)")
	macAddress := flag.String("mac", "00:14:E4:01:23:45", "The eIDC MAC address to use")
	macAddressOverride := flag.String("mac-override", "", "Override and do not validate the MAC address")
	serialNumberOverride := flag.String("serial-override", "", "Override the serial number (normally derived from MAC)")
	firmwareVersion := flag.String("firmware", "3.4.20", "The client's firmware version")
	cardFormat := flag.String("card-format", "short", "The client's card format")
	ipAddress := flag.String("ip", "172.16.1.100", "The IP address of the client")
	configurationKey := flag.String("config-key", "", "The configuration key, which is normally unspecified")
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
read -s ` + defaultSiteKeyEnv + `
<type in your site key>
export ` + defaultSiteKeyEnv + `
client -u https://127.0.0.1:18800
`)
		os.Exit(1)
	}

	var macAddressFinal string
	if len(*macAddressOverride) > 0 {
		macAddressFinal = *macAddressOverride
	} else {
		macAddressFinal = *macAddress
	}

	var serialNumberFinal string
	if len(*serialNumberOverride) > 0 {
		serialNumberFinal = *serialNumberOverride
	} else {
		if len(*macAddressOverride) > 0 {
			serialNumberFinal = client.SerialNumberWithSuffix(strings.ReplaceAll(*macAddressOverride, ":", ""))
		} else {
			sn, err := client.SerialNumberFromMACString(*macAddress)
			if err != nil {
				log.Fatalf("failed to create serial number from mac - %s", err.Error())
			}
			serialNumberFinal = sn
		}
	}

	if len(*serverKey) == 0 {
		var err error
		*serverKey, err = client.RandomServerKey()
		if err != nil {
			log.Fatalf("failed to generate a random server key - %s", err.Error())
		}
	}

	siteKey, ok := os.LookupEnv(*siteKeyEnv)
	if !ok && !*allowEmptySiteKey {
		log.Fatal("a site key was not provided - this can be overridden with command line arguments")
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

	rawGobrResp, err := eidc32proxy.EIDCHTTPResponseBytes(&eidc32proxy.EIDCHTTPResponseData{
		StatusCode: http.StatusOK,
		WrapperBody: &eidc32proxy.EIDCSimpleResponse{
			Cmd:    eidc32proxy.GetoutboundResponseCmd,
			Result: true,
		},
		Body: &eidc32proxy.GetOutboundResponse{
			SiteKey:                siteKey,
			PrimaryHostAddress:     strings.Split(intellimURL.IntelliM.Host, ":")[0],
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
		log.Fatalf("failed to pre-compute response for getOutboundRequest - %s", err.Error())
	}

	// Create a pager before connecting and subscribe so we
	// do not miss any messages.
	messagePager := eidc32proxy.NewMessagePager()
	anyMessages, stopAnyMessages := messagePager.Subscribe(eidc32proxy.SubInfo{
		Category: eidc32proxy.SubMsgCatAny,
	})
	getOutboundRequests, stopGetOutboundsRequests := messagePager.Subscribe(eidc32proxy.SubInfo{
		MsgTypes: []eidc32proxy.MsgType{eidc32proxy.MsgTypeGetoutboundRequest},
	})
	garbageRequests, garbageUnsubFns := client.SubscribeTo(messagePager,
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

	eidcClient, err := client.ConnectWithConfig(client.ConnectionConfig{
		URL:               intellimURL,
		Pager:             messagePager,
		FirstWriteTimeout: 30 * time.Second,
		FirstReadTimeout:  30 * time.Second,
		ServerKey:         *serverKey,
		Request: eidc32proxy.ConnectedRequest{
			SerialNumber:     serialNumberFinal,
			FirmwareVersion:  *firmwareVersion,
			IPAddress:        *ipAddress,
			MacAddress:       macAddressFinal,
			SiteKey:          siteKey,
			ConfigurationKey: *configurationKey,
			CardFormat:       *cardFormat,
		},
	})
	if err != nil {
		unsubAllPagerSubsFn()
		log.Fatalf("failed to connect to %s - %s", target.String(), err.Error())
	}

	controlC := make(chan os.Signal, 1)
	signal.Notify(controlC, os.Interrupt, os.Kill)

	sendWrapperFn := func(raw []byte, msgType eidc32proxy.MsgType) error {
		log.Printf("[notice] automaically responding to '%s' with:\n%s",
			msgType.String(), raw)
		return eidcClient.SendRaw(raw)
	}

	respondTrueErrs := client.TrueDat(sendWrapperFn, garbageRequests...)

OUTER:
	for {
		select {
		case err := <-eidcClient.OnConnClosed():
			if err != nil {
				log.Printf("[fatal] connection ended - %s", err.Error())
			} else {
				log.Println("[done] socket closed")
			}
			break OUTER
		case <-controlC:
			break OUTER
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

	unsubAllPagerSubsFn()
	eidcClient.Close()
}
