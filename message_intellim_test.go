package eidc32proxy

import "testing"

func TestParseDownloadRequest(t *testing.T) {
	testData := "" +
		"POST /eidc/download?username=admin&password=admin&seq=24 HTTP/1.1\r\n" +
		"Host: 192.168.6.40\r\n" +
		"User-Agent: eIDCListener\r\n" +
		"Content-Type: application/binary\r\n" +
		"Content-Length: 17\r\n" +
		"\r\n" +
		"this is some data"
	expected := []byte("this is some data")
	msg, err := ReadMsg([]byte(testData), Southbound)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MsgTypeDownloadRequest {
		t.Fatalf("expected %s, got %s",
			MsgTypeDownloadRequest.String(),
			msg.Type.String())
	}
	if msg.Request == nil {
		t.Fatal("request field must not be nill")
	}
	result := msg.ParseDownloadRequest()
	if len(result) != len(expected) {
		t.Fatalf("got %d bytes, expected %d bytes",
			len(result),
			len(expected))
	}
}
