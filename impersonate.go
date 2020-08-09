package eidc32proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

var (
	eidc32RequestHeaderOrder = []string{
		"POST ",
		"Host: ",
		"Content-Type: ",
		"Content-Length: ",
		"ServerKey:",
	}

	eidc32ResponseHeaderOrder = []string{
		"HTTP",
		serverHeaderName + ":",
		"Content-type:",
		"Content-Length:",
		cacheControlHeaderName + ":",
	}

	serverRequestHeaderOrder = []string{
		"POST",
		"GET",
		"Host:",
		"User-Agent:",
		"Content-Type:",
		"Content-Length:",
	}

	serverResponseHeaderOrder = []string{
		"HTTP",
		"Content-Type:",
		"Content-Length:",
	}

	serverQueryParamOrder = []string{
		"username=",
		"password=",
		"seq=",
	}

	eidc32RequestHeaderRewrite = map[string]string{
		"Serverkey:": "ServerKey:",
	}

	eidc32ResponseHeaderRewrite = map[string]string{
		"Content-Type:":   "Content-type:",
		"Content-Length:": "Content-Length: ",
	}

	serverRequestHeaderRewrite = map[string]string{
		//"Serverkey:":"ServerKey:",
	}

	serverResponseHeaderRewrite = map[string]string{
		//"Content-Type:":"Content-type:",
		//"Content-Length:":"Content-Length:",
	}
)

type eidc32RequestHeaderSort []string

func (s eidc32RequestHeaderSort) Len() int {
	return len(s)
}
func (s eidc32RequestHeaderSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s eidc32RequestHeaderSort) Less(i, j int) bool {
	for _, m := range eidc32RequestHeaderOrder {
		if strings.HasPrefix(strings.ToLower(s[i]), strings.ToLower(m)) {
			return true
		}
		if strings.HasPrefix(strings.ToLower(s[j]), strings.ToLower(m)) {
			return false
		}
	}
	return true
}

type eidc32ResponseHeaderSort []string

func (s eidc32ResponseHeaderSort) Len() int {
	return len(s)
}
func (s eidc32ResponseHeaderSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s eidc32ResponseHeaderSort) Less(i, j int) bool {
	for _, m := range eidc32ResponseHeaderOrder {
		if strings.HasPrefix(strings.ToLower(s[i]), strings.ToLower(m)) {
			return true
		}
		if strings.HasPrefix(strings.ToLower(s[j]), strings.ToLower(m)) {
			return false
		}
	}
	return true
}

type serverRequestHeaderSort []string

func (s serverRequestHeaderSort) Len() int {
	return len(s)
}
func (s serverRequestHeaderSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s serverRequestHeaderSort) Less(i, j int) bool {
	for _, m := range serverRequestHeaderOrder {
		if strings.HasPrefix(strings.ToLower(s[i]), strings.ToLower(m)) {
			return true
		}
		if strings.HasPrefix(strings.ToLower(s[j]), strings.ToLower(m)) {
			return false
		}
	}
	return true
}

type serverResponseHeaderSort []string

func (s serverResponseHeaderSort) Len() int {
	return len(s)
}
func (s serverResponseHeaderSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s serverResponseHeaderSort) Less(i, j int) bool {
	for _, m := range serverResponseHeaderOrder {
		if strings.HasPrefix(strings.ToLower(s[i]), strings.ToLower(m)) {
			return true
		}
		if strings.HasPrefix(strings.ToLower(s[j]), strings.ToLower(m)) {
			return false
		}
	}
	return true
}

type serverQueryParamSort []string

func (s serverQueryParamSort) Len() int {
	return len(s)
}
func (s serverQueryParamSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s serverQueryParamSort) Less(i, j int) bool {
	for _, m := range serverQueryParamOrder {
		if strings.HasPrefix(strings.ToLower(s[i]), strings.ToLower(m)) {
			return true
		}
		if strings.HasPrefix(strings.ToLower(s[j]), strings.ToLower(m)) {
			return false
		}
	}
	return true
}

// impersonate makes small changes to HTTP messages in order to make them
// indistinguishable from those created by the software we're emulating.
func impersonate(in []byte, dir Direction) ([]byte, error) {
	switch {
	case isRequest(in) && dir == Northbound:
		return impersonateEIDC32Request(in)
	case isRequest(in) && dir == Southbound:
		return impersonateServerRequest(in)
	case isResponse(in) && dir == Northbound:
		return impersonateEIDC32Response(in)
	case isResponse(in) && dir == Southbound:
		return impersonateServerResponse(in)
	default:
		return in, errors.New("impersonate() called with neither request nor response")
	}
}

// impersonateEIDC32Request takes an HTTP request (bytes), fixes it up to
// look like a real eIDC32 request.
func impersonateEIDC32Request(in []byte) ([]byte, error) {
	// find the delimiter between header and body
	headerEnd := bytes.Index(in, crlfCRLFBytes) + 2
	if headerEnd <= 0 {
		return nil, errors.New("error parsing eidc32 request slice")
	}

	// parse header text into a slice of strings, fix case, preserve newlines
	var h []string
	s := bufio.NewScanner(bytes.NewReader(in[0:headerEnd]))
	for s.Scan() {
		h = append(h, doEIDC32RequestHeaderRewrite(s.Text())+"\r\n")
	}

	// sort header slice like an eIDC32 would do
	sort.Sort(eidc32RequestHeaderSort(h))

	out := bytes.Buffer{}
	for i := range h {
		out.Write([]byte(h[i]))
	}
	out.Write(in[headerEnd:])
	return out.Bytes(), nil
}

// doEIDC32RequestHeaderRewrite replaces header lines in the input string with
// lines from the eidc32RequestHeaderRewrite map. It's here to fix case
// anomalies, whitespace, etc...
func doEIDC32RequestHeaderRewrite(in string) string {
	for k, v := range eidc32RequestHeaderRewrite {
		if strings.HasPrefix(in, k) {
			return v + in[len(k):]
		}
	}
	return in
}

// impersonateEIDC32Response takes an HTTP response (bytes), fixes it up to
// look like a real eIDC32 request.
func impersonateEIDC32Response(in []byte) ([]byte, error) {
	// find the delimiter between header and body
	headerEnd := bytes.Index(in, crlfCRLFBytes) + 2
	if headerEnd <= 0 {
		return nil, errors.New("error parsing eidc32 response slice")
	}

	// parse header text into a slice of strings, fix case, preserve newlines
	var h []string
	s := bufio.NewScanner(bytes.NewReader(in[0:headerEnd]))
	for s.Scan() {
		// eidc32 server doesn't send "Connection" header
		if strings.HasPrefix(s.Text(), "Connection:") {
			continue
		}
		h = append(h, doEIDC32ResponseHeaderRewrite(s.Text())+"\r\n")
	}

	// sort header slice like an server would do
	sort.Sort(eidc32ResponseHeaderSort(h))

	out := bytes.Buffer{}
	for i := range h {
		out.Write([]byte(h[i]))
	}
	out.Write(in[headerEnd:])
	return out.Bytes(), nil
}

// doEIDC32ResponseHeaderRewrite replaces header lines in the input string with
// lines from the eidc32ResponseHeaderRewrite map. It's here to fix case
// anomalies, whitespace, etc...
func doEIDC32ResponseHeaderRewrite(in string) string {
	for k, v := range eidc32ResponseHeaderRewrite {
		if strings.HasPrefix(in, k) {
			return v + in[len(k):]
		}
	}
	return in
}

// impersonateServerRequest takes an HTTP request (bytes), fixes it up to
// look like a real Infinias application server request.
func impersonateServerRequest(in []byte) ([]byte, error) {
	// find the delimiter between header and body
	headerEnd := bytes.Index(in, crlfCRLFBytes) + 2
	if headerEnd <= 0 {
		return nil, errors.New("error parsing server request slice")
	}

	// parse header text into a slice of strings, fix case, preserve newlines
	var h []string
	s := bufio.NewScanner(bytes.NewReader(in[0:headerEnd]))
	for s.Scan() {
		h = append(h, doServerRequestHeaderRewrite(s.Text())+"\r\n")
	}

	if len(h) < 1 {
		return nil, fmt.Errorf("impossible request has only %d lines", len(h))
	}

	// sort the URL query parameters
	h[0] = doServerQueryParamSort(h[0])

	// sort header slice like a server would do
	sort.Sort(serverRequestHeaderSort(h))

	// write the fixed-up header to a new []byte
	out := bytes.Buffer{}
	for i := range h {
		out.Write([]byte(h[i]))
	}

	// Empty (zero Content-Length) GET requests from the server
	// (eIDCListener) have a bogus extra newline. Add it.
	req, _ := http.ReadRequest(bufio.NewReader(bytes.NewReader(in)))
	switch {
	case req.Method != http.MethodGet:
		break
	case req.UserAgent() != UAeIDCListener:
		break
	case req.ContentLength != 0:
		break
	default:
		out.Write([]byte{13, 10})
	}

	// write the remaining input data to the new output slice.
	out.Write(in[headerEnd:])

	return out.Bytes(), nil
}

// doServerRequestHeaderRewrite replaces header lines in the input string with
// lines from the serverRequestHeaderRewrite map. It's here to fix case
// anomalies, whitespace, etc...
func doServerRequestHeaderRewrite(in string) string {
	for k, v := range serverRequestHeaderRewrite {
		if strings.HasPrefix(in, k) {
			return v + in[len(k):]
		}
	}

	return in
}

// impersonateServerResponse takes an HTTP request (bytes), fixes it up to
// look like a real Infinias application server response.
func impersonateServerResponse(in []byte) ([]byte, error) {
	// find the delimiter between header and body
	headerEnd := bytes.Index(in, crlfCRLFBytes) + 2
	if headerEnd <= 0 {
		return nil, errors.New("error parsing server response slice")
	}

	// parse header text into a slice of strings, fix case, preserve newlines
	var h []string
	s := bufio.NewScanner(bytes.NewReader(in[0:headerEnd]))
	for s.Scan() {
		h = append(h, doServerResponseHeaderRewrite(s.Text())+"\r\n")
	}

	// sort header slice like an eIDC32 would do
	sort.Sort(serverResponseHeaderSort(h))

	out := bytes.Buffer{}
	for i := range h {
		out.Write([]byte(h[i]))
	}
	out.Write(in[headerEnd:])
	return out.Bytes(), nil
}

// doServerResponseHeaderRewrite replaces header lines in the input string with
// lines from the eidc32ResponseHeaderRewrite map. It's here to fix case
// anomalies, whitespace, etc...
func doServerResponseHeaderRewrite(in string) string {
	for k, v := range serverResponseHeaderRewrite {
		if strings.HasPrefix(in, k) {
			return v + in[len(k):]
		}
	}
	return in
}

// doServerQueryParamSort takes the first line of an HTTP request like:
//   "GET /index.html?param1=val1&param2=val2#thing HTTP1.1"
// and returns it with the parameters sorted according to the order
// expressed by the serverQueryParamOrder slice. it's... not very
// pretty.
func doServerQueryParamSort(in string) string {
	// in: "GET /index.html?param1=val1&param2=val2#thing HTTP/1.1"
	//   part[0]: "GET"
	//     part1a: "/index.html?"
	//     part1b: "param1=val1&param2=val2"
	//     part1c: "#thing"
	//   part[2]: "HTTP/1.1"

	lineParts := strings.Split(in, " ")
	if len(lineParts) < 2 {
		return in
	}

	var part1a, part1b, part1c string
	// split string 'in' into components before (part1a) and
	// after (part1c) the query parameters (part1b)
	i := strings.IndexAny(lineParts[1], "?")
	if i < 0 {
		return in
	}
	j := strings.IndexAny(lineParts[1], "#")
	if j >= 0 {
		part1a, part1b, part1c = lineParts[1][:i+1], lineParts[1][i+1:j], lineParts[1][j:]
	} else {
		part1a, part1b = lineParts[1][:i+1], lineParts[1][i+1:]
	}

	// sort the parameters in part1b
	params := serverQueryParamSort(strings.Split(part1b, "&"))
	sort.Sort(params)
	part1b = strings.Join(params, "&")

	lineParts[1] = part1a + part1b + part1c

	return strings.Join(lineParts, " ")
}
