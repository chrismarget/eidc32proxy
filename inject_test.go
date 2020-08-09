package eidc32proxy

import (
	"bytes"
	"log"
	"testing"
)

func TestHeartBeat(t *testing.T) {
	expected :=
		"GET /eidc/heartbeat?password=admin&seq=0&username=admin HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n\r\n"
	msg, err := NewHeartbeatMsg("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	result, err := msg.Marshal()
	if err != nil {
		log.Println("got an error")
		t.Fatal(err)
	}

	if !bytes.Equal(result, []byte(expected)) {
		t.Fatalf("unexpected result")
	}
}
