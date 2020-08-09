package eidc32proxy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

const (
	header = "POST /eidc/connected HTTP/1.1\r\n" +
		"Host: production-webhal-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com:18800\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 217\r\n" +
		"ServerKey: xxxxxxxxxxxxxxxx\r\n" +
		"\r\n"
)

func TestIsRequest(t *testing.T) {
	var td []byte

	// test the minimal possible request line
	td = []byte("GET / HTTP/1.0\r\n")
	if !isRequest(td) {
		t.Fatalf("\"%s\" should have looked like a request", td)
	}

	// test a request line that's longer than our peek()
	td = []byte("GET /very-long-request-string HTTP/1.0\r\n")
	if !isRequest(td) {
		t.Fatalf("\"%s\" should have looked like a request", td)
	}

	// test a bogus request line
	td = []byte("GETT /very-long-request-string HTTP/1.0\r\n")
	if isRequest(td) {
		t.Fatalf("\"%s\" should not have looked like a request", td)
	}

	// test a bogus request line
	td = []byte(" GET / HTTP/1.0\r\n")
	if isRequest(td) {
		t.Fatalf("\"%s\" should not have looked like a request", td)
	}
}

func TestIsResponse(t *testing.T) {
	var td []byte

	// test the minimal possible response line
	td = []byte("HTTP/1.0 200 OK\r\n")
	if !isResponse(td) {
		t.Fatalf("\"%s\" should have looked like a response", td)
	}

	// test a weirdly long response line
	td = []byte("HTTP/111.555 200 OK\r\n")
	if !isResponse(td) {
		t.Fatalf("\"%s\" should have looked like a response", td)
	}

	// bad data : leading space
	td = []byte(" HTTP/1.0 200 OK\r\n")
	if isResponse(td) {
		t.Fatalf("response with leading space is bogus '%s'", td)
	}

	// bad data : second line
	td = []byte("\nHTTP/1.0 200 OK\r\n")
	if isResponse(td) {
		t.Fatalf("response on second line is bogus '%s'", td)
	}
}

func TestPeekHttpHeader(t *testing.T) {
	testHeader := "GET /foo/bar HTTP/1.1\r\n" +
		"Host: webserver:81\r\n" +
		"User-Agent: whatever\r\n\r\n"
	rdr := bufio.NewReader(bytes.NewReader([]byte(testHeader)))
	result, err := peekHttpHeader(rdr)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != testHeader {
		t.Fatalf("results don't match: '%s' and '%s'", result, testHeader)
	}
}

func TestPeekHostHeader(t *testing.T) {
	expected := "foo.bar.com:80"
	testData := "abcd\r\nHost: " + expected + "\r\nABCD\r\n"
	rdr := bufio.NewReader(bytes.NewReader([]byte(testData)))
	result, err := peekHostHeaderValue(rdr)
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Fatalf("results don't match: '%s' and '%s'", result, expected)
	}
}

func TestPeekLoginInfo(t *testing.T) {
	testData := "POST /eidc/connected HTTP/1.1\r\n" +
		"Host: production-webhal-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com:18800\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 217\r\n" +
		"ServerKey: xxxxxxxxxxxxxxxx\r\n\r\n" +
		`{"serialNumber":"0x000000123456", "firmwareVersion":"3.4.20", ` +
		`"ipAddress":"172.16.1.50", "macAddress":"00:14:E4:12:34:56", ` +
		`"siteKey":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", ` +
		`"configurationKey":"", "cardFormat":"short"}`

	br := bufio.NewReader(strings.NewReader(testData))
	li, err := peekLoginInfo(br)
	if err != nil {
		t.Fatal(err)
	}
	expectedHost := "production-webhal-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com:18800"
	if li.Host != expectedHost {
		t.Fatalf("expected:\n\t%s\ngot:\n\t%s\n", expectedHost, li.Host)
	}
}

func TestSplitHttpMsg(t *testing.T) {
	testData := "" +
		"foo1\r\n" +
		"bar1\r\n" +
		"\r\n" +
		"foo2\r\n" +
		"bar2\r\n" +
		"\r\n"
	expected1 := "foo1\r\nbar1\r\n\r\n"
	expected2 := "foo2\r\nbar2\r\n\r\n"
	testRdr := bufio.NewReader(strings.NewReader(testData))
	s := bufio.NewScanner(testRdr)
	s.Split(SplitHttpMsg)

	buf := make([]byte, 3)
	s.Buffer(buf, 2^16)

	s.Scan()
	if string(s.Bytes()) != expected1 {
		t.Fatalf("expected %s, got %s", expected1, string(s.Bytes()))
	}

	s.Scan()
	if string(s.Bytes()) != expected2 {
		t.Fatalf("expected %s, got %s", expected2, string(s.Bytes()))
	}
}
