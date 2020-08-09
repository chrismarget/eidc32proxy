package eidc32proxy

import (
	"testing"
)

func TestParseControllerLogin(t *testing.T) {
	testData := `{"serialNumber":"0x000000123456", "firmwareVersion":"3.4.20", "ipAddress":"172.16.50.50", "macAddress":"00:14:E4:12:34:56", "siteKey":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx", "configurationKey":"", "cardFormat":"short"}`
	_, err := parseControllerLoginBytes([]byte(testData))
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseDoor0x2fLockStatusResponse(t *testing.T) {
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  70\r\n" +
			"Cache-Control: no-cache\r\n" +
			"\r\n" +
			`{"result":true, "cmd":"DOOR/LOCKSTATUS", "body":{"status":"Unlocked"}}`
	expected := "Unlocked"
	msg, err := ReadMsg([]byte(testData), Northbound)
	if err != nil {
		t.Fatal(err)
	}
	msgType := msg.GetType()
	if msgType != MsgTypeDoor0x2fLockStatusResponse {
		t.Fatalf("expected %s", MsgTypeDoor0x2fLockStatusResponse.String())
	}
	dlsr, err := msg.ParseDoor0x2fLockStatusResponse()
	if err != nil {
		t.Fatal(err)
	}
	if dlsr.Status != expected {
		t.Fatalf("expected %s, got %s", expected, dlsr.Status)
	}
}

func TestMessage_ParseAddFormatsResponse(t *testing.T) {
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  62\r\n" +
			"Cache-Control: no-cache\r\n" +
			"\r\n" +
			`{"result":true, "cmd":"ADDFORMATS", "body":{"formatsAdded":3}}`
	expected := 3
	msg, err := ReadMsg([]byte(testData), Northbound)
	if err != nil {
		t.Fatal(err)
	}
	msgType := msg.GetType()
	if msgType != MsgTypeAddFormatsResponse {
		t.Fatalf("expected %s, got %s", MsgTypeAddFormatsResponse.String(), msgType)
	}
	afr, err := msg.ParseAddFormatsResponse()
	if err != nil {
		t.Fatal(err)
	}
	if afr.FormatsAdded != expected {
		t.Fatalf("expected %d, got %d", expected, afr.FormatsAdded)
	}
}
