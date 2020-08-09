package eidc32proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Various strings used for searching and building HTTP messages.
//
// Only use these if you know what you are doing.
const (
	UAeIDCWebServer = "eIDC32 WebServer"
	http10Proto     = "HTTP/1.0"
	noCache         = "no-cache"
)

// Various HTTP headers by name only. Does not include colon or space chars.
const (
	hostHeader             = "host:"
	crlf                   = "\r\n"
	crlfcrlf               = "\r\n\r\n"
	contentLengthWithColon = "content-length:"
	UAeIDCListener         = "eIDCListener"
	serverHeaderName       = "Server"
	cacheControlHeaderName = "Cache-Control"
	contentTypeHeaderName  = "Content-Type"
	serverKeyHeaderName    = "ServerKey"
)

var (
	crlfBytes     = []byte(crlf)
	crlfCRLFBytes = []byte(crlfcrlf)
	reqMethods    = [][]byte{
		[]byte("OPTIONS "),
		[]byte("GET "),
		[]byte("HEAD "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("TRACE "),
		[]byte("CONNECT "),
	}
	httpCLHeader = []byte(contentLengthWithColon)
)

// isRequest returns true if the passed reader looks like
// it contains an HTTP request.
func isRequest(b []byte) bool {
	for _, m := range reqMethods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

// isResponse returns true if the passed reader looks like
// it contains an HTTP response.
func isResponse(b []byte) bool {
	i := bytes.Index(b, crlfBytes)
	if i <= 0 {
		return false
	}
	re := regexp.MustCompile("^HTTP/[0-9]+.[0-9]+ ")
	return re.Match(b[:i])
}

// SplitHttpMsg is a scanner split function. It causes the scanner parse out
// individual http messages. A message ends at CRLF+CRLF unless a
// "Content-Length:" header appears, in which case the message ends
// Content-Length bytes after the CRLF+CRLF.
func SplitHttpMsg(data []byte, atEOF bool) (advance int, token []byte, err error) {
	//todo need to do something with atEOF
	var headerSize int
	var contentLength int
	// Look for CRLF+CRLF
	if headerSize = bytes.Index(data, crlfCRLFBytes); headerSize >= 0 {
		// First, adjust i so that it points at the *end* of the delimiter, not
		// than the beginning. This is safe (no nil pointer dereference) because
		// we already know the newline characters are there.
		headerSize += len(crlfCRLFBytes)

		contentLength, err = getContentLength(data[:headerSize])
		if err != nil {
			return 0, nil, err
		}

		// ask for more data if we don't have the whole body yet
		if headerSize+contentLength > len(data) {
			return 0, nil, nil
		}

		// eIDCListener bug: It sends a bogus CRLF with GET messages. Check for
		// and include extra newline data beyond where this request
		// should have ended.
		var buggyExtraGarbage int
		for len(data) > headerSize+contentLength+buggyExtraGarbage {
			if unicode.IsSpace(rune(data[headerSize+contentLength+buggyExtraGarbage])) {
				buggyExtraGarbage++
			} else {
				break
			}
		}

		count := headerSize + contentLength + buggyExtraGarbage
		return count, data[:count], nil
	}

	// crlfcrlf not available - ask for more data
	return 0, nil, nil
}

// getContentLength extracts the content-length value from an http header.
// If not present in the header return value will be -1
func getContentLength(in []byte) (int, error) {
	contentLength := -1
	var err error
	scanner := bufio.NewScanner(bytes.NewReader(in))
	for scanner.Scan() {
		// Find the line beginning with "Content-Length:"
		if bytes.HasPrefix(bytes.ToLower(scanner.Bytes()), httpCLHeader) {
			// Extract the Content Length
			re := regexp.MustCompile("[0-9]+")
			contentLength, err = strconv.Atoi(string(re.Find(scanner.Bytes())))
		}
	}
	return contentLength, err
}

// peekHttpHeader assumes input is an HTTP request/response, will have a
// CRLFCRLF sequence. It returns everything including that delimiter,
// suitable for parsing by http.Read<stuff>()
func peekHttpHeader(in *bufio.Reader) ([]byte, error) {
	var err error
	var test []byte

	// loop until "\r\n\r\n"
	for i := 4; ; i++ {
		test, err = in.Peek(i)
		if err != nil {
			return nil, err
		}
		if bytes.HasSuffix(test, crlfCRLFBytes) {
			return test[:len(test)], nil
		}
	}
}

// peekHostHeaderValue finds the "host: xyz" header in a bufio.reader using the
// peek() method. It's here to dig out the name of the Real Server (tm) that
// the proxy needs to connect to, without actually consuming any data from the
// reader. The reader can then be used by the message relay functions.
func peekHostHeaderValue(in *bufio.Reader) (string, error) {
	var i, j int

	// loop until we find "\r\nhost:", leave 'i' pointing at the end of it.
	for i = 0; ; i++ {
		test, err := in.Peek(i)
		if err != nil {
			return "", err
		}
		if bytes.HasSuffix(bytes.ToLower(test), []byte(crlf+hostHeader)) {
			break
		}
	}

	// loop until we find "\r\n", leave j pointing at the beginning of it.
	for j = i + len(hostHeader); ; j++ {
		test, err := in.Peek(j)
		if err != nil {
			return "", err
		}
		if bytes.HasSuffix(test, crlfBytes) {
			j -= len(crlf)
			break
		}
	}

	found, err := in.Peek(j)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(found[i:j])), nil
}

// peekLoginInfo extracts LoginInfo data from a bufio.Reader without
// actually pulling data from the reader (peek)
func peekLoginInfo(in *bufio.Reader) (*LoginInfo, error) {
	// start by extracting the HTTP header we assume is going to be here
	hdrBytes, err := peekHttpHeader(in)
	if err != nil {
		return nil, err
	}

	// now grab the rest of the HTTP message
	contentLength, err := getContentLength(hdrBytes)
	if err != nil {
		return nil, err
	}

	if contentLength <= 0 {
		return nil, fmt.Errorf("peekLoginInfo can't find content-length")
	}

	httpMsgBytes, err := in.Peek(len(hdrBytes) + contentLength)
	if err != nil {
		return nil, err
	}

	// Ultimately we're looking to construct a LoginInfo. This info is sent as
	// the first HTTP request in an eIDC32 session. It HAS TO BE a request.
	if !isRequest(httpMsgBytes) {
		return nil, fmt.Errorf("initial message not an HTTP request:'%s'",
			string(httpMsgBytes))
	}

	// Parse the request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(httpMsgBytes)))
	if err != nil {
		return nil, err
	}

	// We're still looking to construct a LoginInfo. Make sure this request
	// contains that information.
	if !isControllerLogin(req) {
		return nil, fmt.Errorf("initial message not a controller login")
	}

	// ServerKey will be the value at the first instance of "Serverkey" found
	// in the http header.
	var serverKey string
	if len(req.Header["Serverkey"]) > 0 {
		serverKey = req.Header["Serverkey"][0]
	}

	// The body of the request contains most of the interesting stuff. Grab it.
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	// parse the request body into a connectedReq
	connectedReq, err := parseControllerLoginBytes(body)
	if err != nil {
		return nil, err
	}
	return &LoginInfo{
		Host:         req.Host,
		ServerKey:    serverKey,
		ConnectedReq: connectedReq,
	}, nil
}
