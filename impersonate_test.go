package eidc32proxy

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"testing"
)

func TestEidc32RequestHeaderSort(t *testing.T) {
	var test eidc32RequestHeaderSort
	test = append(test, "Content-Type:   line 3")
	test = append(test, "POST            line 1")
	test = append(test, "HOST:           line 2")
	test = append(test, "ServerKey:      line 5")
	test = append(test, "Content-Length: line 4")

	var expected eidc32RequestHeaderSort
	expected = append(expected, "POST            line 1")
	expected = append(expected, "HOST:           line 2")
	expected = append(expected, "Content-Type:   line 3")
	expected = append(expected, "Content-Length: line 4")
	expected = append(expected, "ServerKey:      line 5")

	sort.Sort(test)

	if len(test) != len(expected) {
		t.Fatalf("slice lengths no good")
	}

	for i := range test {
		if test[i] != expected[i] {
			t.Fatalf("sort failure at line %d", i)
		}
	}
}

func TestEidc32ResponseHeaderSort(t *testing.T) {
	var test eidc32ResponseHeaderSort
	test = append(test, "Server: eIDC32 WebServeter     line 2")
	test = append(test, "Cache-Control: no-cache        line 5")
	test = append(test, "Content-Length:  360           line 4")
	test = append(test, "Content-type: application/json line 3")
	test = append(test, "HTTP/1.0 200 OK                line 1")

	var expected eidc32ResponseHeaderSort
	expected = append(expected, "HTTP/1.0 200 OK                line 1")
	expected = append(expected, "Server: eIDC32 WebServeter     line 2")
	expected = append(expected, "Content-type: application/json line 3")
	expected = append(expected, "Content-Length:  360           line 4")
	expected = append(expected, "Cache-Control: no-cache        line 5")

	sort.Sort(test)

	if len(test) != len(expected) {
		t.Fatalf("slice lengths no good")
	}

	for i := range test {
		if test[i] != expected[i] {
			t.Fatalf("sort failure at line %d", i)
		}
	}
}

func TestServerRequestHeaderSort(t *testing.T) {
	var test serverRequestHeaderSort
	test = append(test, "Content-Type:   line 3")
	test = append(test, "POST            line 1")
	test = append(test, "HOST:           line 2")
	test = append(test, "ServerKey:      line 5")
	test = append(test, "Content-Length: line 4")

	var expected serverRequestHeaderSort
	expected = append(expected, "POST            line 1")
	expected = append(expected, "HOST:           line 2")
	expected = append(expected, "Content-Type:   line 3")
	expected = append(expected, "Content-Length: line 4")
	expected = append(expected, "ServerKey:      line 5")

	sort.Sort(test)

	if len(test) != len(expected) {
		t.Fatalf("slice lengths no good")
	}

	for i := range test {
		if test[i] != expected[i] {
			t.Fatalf("sort failure at line %d", i)
		}
	}
}

func TestServerResponseHeaderSort(t *testing.T) {
	var test serverResponseHeaderSort
	test = append(test, "Content-Length: 32             line 3")
	test = append(test, "HTTP/1.1 200 OK                line 1")
	test = append(test, "Content-Type: application/json line 2")

	var expected serverResponseHeaderSort
	expected = append(expected, "HTTP/1.1 200 OK                line 1")
	expected = append(expected, "Content-Type: application/json line 2")
	expected = append(expected, "Content-Length: 32             line 3")

	sort.Sort(test)

	if len(test) != len(expected) {
		t.Fatalf("slice lengths no good")
	}

	for i := range test {
		if test[i] != expected[i] {
			log.Println(test[i])
			log.Println(expected[i])
			t.Fatalf("sort failure at line %d", i)
		}
	}
}

func TestNorthboundData(t *testing.T) {
	nbdata, err := ioutil.ReadFile("test_northbound.dat")
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(bufio.NewReader(bytes.NewReader(nbdata)))
	s.Split(SplitHttpMsg)
	for s.Scan() {
		switch {
		case isRequest(s.Bytes()):
			request, err := parseAndRebuildHTTPRequest(s.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			impostorRequest, err := impersonateEIDC32Request(request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.Bytes(), impostorRequest) {
				t.Fatalf("original and rebuilt requests don't match:\nvvvvvv\n%s\n^^^^^^\nvvvvvv\n%s\n^^^^^^\n", string(s.Bytes()), string(impostorRequest))
			}
		case isResponse(s.Bytes()):
			response, err := parseAndRebuildHTTPResponse(s.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			impostorResponse, err := impersonateEIDC32Response(response)
			if !bytes.Equal(s.Bytes(), impostorResponse) {
				log.Println(impostorResponse)
				log.Println(s.Bytes())
				t.Fatalf("original and rebuilt responses don't match:\nvvvvvv\n%s\n^^^^^^\nvvvvvv\n%s\n^^^^^^\n", string(s.Bytes()), string(impostorResponse))
			}
		default:
			t.Fatalf("neither request nor response:\nvvvvvv\n%s\n^^^^^^\n", s.Text())
		}
	}
}

func TestSouthboundData(t *testing.T) {
	sbdata, err := ioutil.ReadFile("test_southbound.dat")
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(bufio.NewReader(bytes.NewReader(sbdata)))
	s.Split(SplitHttpMsg)
	for s.Scan() {
		switch {
		case isRequest(s.Bytes()):
			request, err := parseAndRebuildHTTPRequest(s.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			impostorRequest, err := impersonateServerRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.Bytes(), impostorRequest) {
				t.Fatalf("original and rebuilt requests don't match:\nvvvvvv\n%s\n^^^^^^\nvvvvvv\n%s\n^^^^^^\n", string(s.Bytes()), string(impostorRequest))
			}
		case isResponse(s.Bytes()):
			response, err := parseAndRebuildHTTPResponse(s.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			impostorResponse, err := impersonateServerResponse(response)
			if !bytes.Equal(s.Bytes(), impostorResponse) {
				t.Fatalf("original and rebuilt responses don't match:\nvvvvvv\n%s\n^^^^^^\nvvvvvv\n%s\n^^^^^^\n", string(s.Bytes()), string(impostorResponse))
			}
		default:
			t.Fatalf("neither request nor response:\nvvvvvv\n%s\n^^^^^^\n", s.Text())
		}
	}
}

// parseAndRebuildHTTPRequest is a testing function that parses an HTTP request
// and then rebuilds it using the standard libraries. It takes bytes and returns
// bytes, but probably not the same string due differences in the http library.
// the returned strings are then used to test the impostor functions.
func parseAndRebuildHTTPRequest(in []byte) ([]byte, error) {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(in)))
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	r.Header.Set("User-Agent", r.Header.Get("User-Agent"))
	r.Body = ioutil.NopCloser(bytes.NewReader(b))
	out := bytes.Buffer{}
	err = r.Write(&out)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// parseAndRebuildHTTPResponse is a testing function that parses an HTTP request
// and then rebuilds it using the standard libraries. It takes bytes and returns
// bytes, but probably not the same string due differences in the http library.
// the returned strings are then used to test the impostor functions.
func parseAndRebuildHTTPResponse(in []byte) ([]byte, error) {
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(in)), nil)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(b))
	out := bytes.Buffer{}
	err = r.Write(&out)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func TestImpersonateEIDC32Restponse(t *testing.T) {
	testData := "HTTP/1.0 200 OK\r\n" +
		"Server: eIDC32 WebServer\r\n" +
		"Content-type: application/json\r\n" +
		"Content-Length:  359\r\n" +
		"Cache-Control: no-cache\r\n" +
		"\r\n"
	body := `{"result":true, "cmd":"GETOUTBOUND", "body":{"siteKey":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "primaryHostAddress":"xxxxxxxxxx-xxxxxx-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com", "primaryPort":18800, "secondaryHostAddress":"11.22.33.44", "secondaryPort":18800, "primarySsl":1, "secondarySsl":1, "retryInterval":1, "maxRandomRetryInterval":60, "enabled":1}}`
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader([]byte(testData))), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body = ioutil.NopCloser(bytes.NewReader([]byte(body)))
	out := bytes.Buffer{}

	err = r.Write(&out)
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := impersonateEIDC32Response(out.Bytes())

	if !bytes.Equal([]byte(testData+body), impostor) {
		t.Fatal("impostor data doesn't match original data")
	}
}

func TestDoServerQueryParamSort(t *testing.T) {
	expected1 := "GET /eidc/getoutbound\r\n"
	testData1 := "GET /eidc/getoutbound\r\n"
	result1 := doServerQueryParamSort(testData1)
	if expected1 != result1 {
		t.Fatalf("strings don't match:\n>%s<\n>%s<", expected1, result1)
	}

	expected2 := "GET /eidc/getoutbound#foo\r\n"
	testData2 := "GET /eidc/getoutbound#foo\r\n"
	result2 := doServerQueryParamSort(testData2)
	if expected2 != result2 {
		t.Fatalf("strings don't match:\n>%s<\n>%s<", expected2, result2)
	}

	expected3 := "GET /eidc/getoutbound?username=admin&password=admin&seq=1 HTTP/1.1\r\n"
	testData3 := "GET /eidc/getoutbound?username=admin&password=admin&seq=1 HTTP/1.1\r\n"
	result3 := doServerQueryParamSort(testData3)
	if expected3 != result3 {
		t.Fatalf("strings don't match:\n>%s<\n>%s<", expected3, result3)
	}

	expected4 := "GET /eidc/getoutbound?username=admin&password=admin&seq=1#foo HTTP/1.1\r\n"
	testData4 := "GET /eidc/getoutbound?username=admin&password=admin&seq=1#foo HTTP/1.1\r\n"
	result4 := doServerQueryParamSort(testData4)
	if expected4 != result4 {
		t.Fatalf("strings don't match:\n>%s<\n>%s<", expected4, result4)
	}

	expected5 := "GET /eidc/getoutbound?username=admin&password=admin&seq=1 HTTP/1.1\r\n"
	testData5 := "GET /eidc/getoutbound?password=admin&seq=1&username=admin HTTP/1.1\r\n"
	result5 := doServerQueryParamSort(testData5)
	if expected5 != result5 {
		t.Fatalf("strings don't match:\n>%s<\n>%s<", expected5, result5)
	}

	expected6 := "GET /eidc/getoutbound?username=admin&password=admin&seq=1#foo HTTP/1.1\r\n"
	testData6 := "GET /eidc/getoutbound?password=admin&seq=1&username=admin#foo HTTP/1.1\r\n"
	result6 := doServerQueryParamSort(testData6)
	if expected6 != result6 {
		t.Fatalf("strings don't match:\n>%s<\n>%s<", expected6, result6)
	}
}
