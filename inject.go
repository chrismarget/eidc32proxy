package eidc32proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
)

const (
	user        = "username"
	pass        = "password"
	methodHttp  = "http"
	host        = "192.168.6.40"
	eidcListner = "eIDCListener"
)

func NewHeartbeatMsg(username string, password string) (*Message, error) {
	values := url.Values{}
	values.Set(user, username)
	values.Set(pass, password)
	values.Set(serverRequestSequenceParam, "0")
	heartbeatUrl := url.URL{
		Scheme:   methodHttp,
		Host:     host,
		Path:     heartbeatRequestURI,
		RawQuery: values.Encode(),
	}
	req, err := http.NewRequest(http.MethodGet, heartbeatUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(ua, eidcListner)
	msg := &Message{
		direction: Southbound,
		Request:   req,
		lock:      &sync.Mutex{},
	}
	return msg, nil
}

// IntellimHTTPRequestBytes returns a []byte representing the raw HTTP request
// to send to an IntelliM instance.
func IntellimHTTPRequestBytes(requestData *IntellimHTTPRequestData) ([]byte, error) {
	eidcMessage, err := IntellimHTTPRequestMsg(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate eidc message - %w", err)
	}

	return eidcMessage.Marshal()
}

// IntellimHTTPRequestMsg returns a *Message representing the HTTP request
// to send to an IntelliM instance.
func IntellimHTTPRequestMsg(requestData *IntellimHTTPRequestData) (*Message, error) {
	req, err := IntellimHTTPRequest(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate http request - %w", err)
	}

	// TODO: Awful hack to ensure Message.Body is non-nil,
	//  and to ensure that req.Body is not depleted.
	buffer := bytes.NewBuffer(nil)
	tee := io.TeeReader(req.Body, buffer)
	raw, err := ioutil.ReadAll(tee)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body for crazy hack - %w", err)
	}
	req.Body = ioutil.NopCloser(buffer)

	return &Message{
		Request: req,
		Body:    raw,
		lock:    &sync.Mutex{},
	}, nil
}

// IntellimHTTPRequest returns a *http.Request to send to an IntelliM instance.
func IntellimHTTPRequest(requestData *IntellimHTTPRequestData) (*http.Request, error) {
	if requestData.URL == nil {
		return nil, fmt.Errorf("url cannot be nil")
	}

	if len(requestData.Method) == 0 {
		return nil, fmt.Errorf("method cannot be empty ")
	}

	if len(requestData.ServerKey) == 0 {
		return nil, fmt.Errorf("server key cannot be empty")
	}

	var bodyReader io.Reader
	if requestData.Body != nil {
		jsonBodyRaw, ok := requestData.Body.([]byte)
		if !ok {
			var err error
			jsonBodyRaw, err = json.Marshal(requestData.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal body into json - %w", err)
			}
		}
		bodyReader = bytes.NewReader(jsonBodyRaw)
	}

	finalURL := requestData.URL
	if len(requestData.SubPath) > 0 {
		var err error
		finalURL, err = finalURL.Parse(requestData.SubPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse provided subpath of '%s' - %w", requestData.SubPath, err)
		}
	}

	req, err := http.NewRequest(requestData.Method, finalURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate http request - %w", err)
	}

	req.Header.Set(serverKeyHeaderName, requestData.ServerKey)
	if bodyReader != nil {
		req.Header.Add(contentTypeHeaderName, ApplicationJSON)
	}

	for k, vs := range requestData.Headers {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	return req, nil
}

// IntellimHTTPRequestData is the data that will be used to construct
// a HTTP request to send to an IntelliM instance.
type IntellimHTTPRequestData struct {
	// URL is the *url.URL of the IntelliM instance.
	URL *url.URL

	// Headers are optional HTTP headers to apply to the request's
	// headers. If this field contains a header already present in
	// the new request's headers, the request's header value is
	// replaced with the value from this field.
	Headers http.Header

	// SubPath is an optional path to append to the URL in
	// the HTTP request.
	SubPath string

	// Method is the HTTP method to use in the HTTP request.
	Method string

	// ServerKey is the server key to use in the HTTP header.
	ServerKey string

	// Body is the optional body to append to the HTTP message.
	// This can be a data structure with JSON tagged fields,
	// or a []byte.
	Body interface{}
}

// EIDCHTTPResponseBytes returns a []byte representing the raw HTTP response
// to send to an IntelliM instance. The message data is manipulated to appear
// like a real eIDC32's response using the "impersonate*" functions.
func EIDCHTTPResponseBytes(responseData *EIDCHTTPResponseData) ([]byte, error) {
	eidcMessage, err := EIDCHTTPResponseMsg(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate eidc message - %w", err)
	}

	raw, err := eidcMessage.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message to bytes - %w", err)
	}

	if eidcMessage.Request != nil {
		return impersonateEIDC32Request(raw)
	}

	return impersonateEIDC32Response(raw)
}

// EIDCHTTPResponseMsg returns a *Message representing the HTTP response
// to send to an IntelliM instance.
func EIDCHTTPResponseMsg(responseData *EIDCHTTPResponseData) (*Message, error) {
	resp, err := EIDCHTTPResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate http response - %w", err)
	}

	// TODO: Awful hack to ensure Message.Body is non-nil,
	//  and to ensure that req.Body is not depleted.
	buffer := bytes.NewBuffer(nil)
	tee := io.TeeReader(resp.Body, buffer)
	raw, err := ioutil.ReadAll(tee)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for crazy hack - %w", err)
	}
	resp.Body = ioutil.NopCloser(buffer)

	return &Message{
		Response: resp,
		Body:     raw,
		lock:     &sync.Mutex{},
	}, nil
}

// EIDCHTTPResponse returns a *http.Response to send to an IntelliM instance.
func EIDCHTTPResponse(responseData *EIDCHTTPResponseData) (*http.Response, error) {
	if responseData.StatusCode == 0 {
		return nil, fmt.Errorf("http response status code cannot be 0")
	}

	var jsonBodyRaw []byte
	if responseData.Body != nil {
		var ok bool
		jsonBodyRaw, ok = responseData.Body.([]byte)
		if !ok {
			var err error
			jsonBodyRaw, err = json.Marshal(responseData.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal body into json - %w", err)
			}
		}
	}
	if responseData.WrapperBody != nil {
		var err error
		if len(jsonBodyRaw) == 0 {
			jsonBodyRaw, err = json.Marshal(&responseData.WrapperBody)
		} else {
			jsonBodyRaw, err = json.Marshal(responseData.WrapperBody.AddBody(jsonBodyRaw))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to marshal wrapper body into json - %w", err)
		}
	}

	resp := &http.Response{
		Status:     http.StatusText(responseData.StatusCode),
		StatusCode: responseData.StatusCode,
		Proto:      http10Proto,
		ProtoMajor: 1,
		ProtoMinor: 0,
		Header:     make(http.Header),
	}

	resp.Header.Add(cacheControlHeaderName, noCache)
	resp.Header.Add(serverHeaderName, UAeIDCWebServer)

	if len(jsonBodyRaw) > 0 {
		resp.ContentLength = int64(len(jsonBodyRaw))
		resp.Header.Add(contentTypeHeaderName, ApplicationJSON)
		resp.Body = ioutil.NopCloser(bytes.NewReader(jsonBodyRaw))
	}

	for k, vs := range responseData.Headers {
		resp.Header.Del(k)
		for _, v := range vs {
			resp.Header.Add(k, v)
		}
	}

	return resp, nil
}

// EIDCHTTPResponseData is the data that will be used to construct
// a HTTP response to an existing IntelliM HTTP request.
type EIDCHTTPResponseData struct {
	// StatusCode is the HTTP status code to include in the response.
	StatusCode int

	// Headers are optional HTTP headers to apply to the response's
	// headers. If this field contains a header already present in
	// the new response's headers, the response's header value is
	// replaced with the value from this field.
	Headers http.Header

	// WrapperBody, if non-nil, is the EIDCSimpleResponse to
	// use in the HTTP message body. If both WrapperBody and Body are
	// non-nil, then the EIDCSimpleResponse will be upgraded
	// into a new EIDCBodyResponse that includes Body.
	WrapperBody *EIDCSimpleResponse

	// Body is the optional body to append to the HTTP message.
	// This can be a data structure with JSON tagged fields,
	// or a []byte.
	//
	// See WrapperBody for additional information.
	Body interface{}
}

// ReplaceHTTPHeaderValue replaces the value of the specified header in the
// provided raw HTTP message with an arbitrary value. The header should be
// of the format "<header-name>: ". For example:
//	contentLength := []byte("Content-Length: ")
//
// This helper method is useful for experimenting with unexpected HTTP header
// values that are not permitted by the types and logic employed by Go's
// http library.
func ReplaceHTTPHeaderValue(headerBytes []byte, newValue []byte, rawHTTPMessage []byte) ([]byte, error) {
	headerLen := len(headerBytes)

	headerStartIndex := bytes.Index(rawHTTPMessage, headerBytes)
	if headerStartIndex < 0 {
		return nil, fmt.Errorf("failed to find header in provided message")
	}

	eolInfex := bytes.IndexAny(rawHTTPMessage[headerStartIndex+headerLen:], "\r\n")
	if eolInfex < 0 {
		return nil, fmt.Errorf("failed to find end of line after header value")
	}

	eolInfex = headerStartIndex + headerLen + eolInfex

	return bytes.Replace(rawHTTPMessage,
		append(headerBytes, rawHTTPMessage[headerStartIndex+headerLen:eolInfex]...),
		append(headerBytes, newValue...),
		1), nil
}

func NewEventAckMsg(username string, password string, id int) (*Message, error) {
	// todo use intellimUrl()
	values := url.Values{}
	values.Set(user, username)
	values.Set(pass, password)
	values.Set(serverRequestSequenceParam, "0")

	eventAckUrl := url.URL{
		Scheme:   methodHttp,
		Host:     host,
		Path:     eventAckRequestURI,
		RawQuery: values.Encode(),
	}

	ear := EventAckRequest{
		EventIds: []int{id},
	}

	body, err := json.Marshal(ear)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, eventAckUrl.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set(ua, eidcListner)

	msg := &Message{
		direction: Southbound,
		Request:   req,
		Body:      body,
		lock:      &sync.Mutex{},
	}

	return msg, nil
}

func NewLockStatusMsg(username string, password string, status lockstatus) (*Message, error) {
	imUrl := intellimUrl(doorLockStatusRequestURI, username, password)
	dlsr := Door0x2fLockStatusRequest{
		Status:   status.String(),
		Duration: -1,
	}
	body, err := json.Marshal(dlsr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, imUrl.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set(ua, eidcListner)

	msg := &Message{
		direction: Southbound,
		Request:   req,
		Body:      body,
		lock:      &sync.Mutex{},
	}

	return msg, nil
}

func intellimUrl(path string, username string, password string) url.URL {
	v := url.Values{}
	v.Set(user, username)
	v.Set(pass, password)
	v.Set(serverRequestSequenceParam, "0")

	u := url.URL{
		Scheme:   methodHttp,
		Host:     host,
		Path:     path,
		RawQuery: v.Encode(),
	}
	return u
}
