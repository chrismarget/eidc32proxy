package eidc32proxy

import (
	"encoding/json"
	"log"
	"testing"
)

func TestNorthboundRequest(t *testing.T) {
	testDir := Northbound
	testData :=
		"POST /eidc/connected HTTP/1.1\r\n" +
			"Host: production-webhal-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com:18800\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 217\r\n" +
			"ServerKey: xxxxxxxxxxxxxxxx\r\n\r\n" +
			`{"serialNumber":"0x000000123456", "firmwareVersion":"3.4.20", "ipAddress":"172.16.1.10", "macAddress":"00:14:E4:12:34:56", "siteKey":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "configurationKey":"", "cardFormat":"short"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("type:", msg.GetType())
	_ = msg
}

func TestNorthboundGetOutboundResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  359\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"GETOUTBOUND", "body":{"siteKey":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "primaryHostAddress":"xxxxxxxxxx-xxxxxx-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com", "primaryPort":18800, "secondaryHostAddress":"11.22.33.44", "secondaryPort":18800, "primarySsl":1, "secondarySsl":1, "retryInterval":1, "maxRandomRetryInterval":60, "enabled":1}}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeGetoutboundResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestNorthboundSetTimeResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  32\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"SETTIME"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeSetTimeResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestNorthboundSetWebUserResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  35\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"SETWEBUSER"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeSetWebUserResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestNorthboundEnableEventsResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  37\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"ENABLEEVENTS"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeEnableEventsResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestNorthboundGetPointStatusResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  39\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"GETPOINTSTATUS"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeGetPointStatusResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestNorthboundPointStatusRequest(t *testing.T) {
	testDir := Northbound
	testData :=
		"POST /eidc/pointStatus HTTP/1.1\r\n" +
			"Host: xxxxxxxxxx-xxxxxx-xxxxxxxxxxxxxxxx.elb.us-east-1.amazonaws.com:18800\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 92\r\n" +
			"ServerKey: 0123456789abcdef\r\n\r\n" +
			`{"time":"2019-11-01T18:50:51-05:00", "points":[{"pointId":7,"oldStatus":0,"newStatus":129}]}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypePointStatusRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

	expectedTime := "2019-11-01T18:50:51-05:00"
	expectedPoints := []Point{Point{
		PointID:   7,
		OldStatus: 0,
		NewStatus: 129,
	}}

	ps, err := msg.ParsePointStatusRequest()
	if err != nil {
		t.Fatal(err)
	}

	if expectedTime != ps.Time {
		t.Fatalf("time mismatch")
	}

	for i := range ps.Points {
		if expectedPoints[i] != ps.Points[i] {
			t.Fatalf("unexpected point data")
		}
	}
}

func TestNorthboundDoor0x2fLockStatusResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  70\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"DOOR/LOCKSTATUS", "body":{"status":"Unlocked"}}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeDoor0x2fLockStatusResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestNorthboundEventAckResponse(t *testing.T) {
	testDir := Northbound
	testData :=
		"HTTP/1.0 200 OK\r\n" +
			"Server: eIDC32 WebServer\r\n" +
			"Content-type: application/json\r\n" +
			"Content-Length:  33\r\n" +
			"Cache-Control: no-cache\r\n\r\n" +
			`{"result":true, "cmd":"EVENTACK"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeEventAckResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestSouthboundConnectedResponse(t *testing.T) {
	testDir := Southbound
	testData :=
		"HTTP/1.1 200 OK\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 32\r\n\r\n" +
			`{"serverKey":"xxxxxxxxxxxxxxxx"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeConnectedResponse
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestSouthboundGetoutboundRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"GET /eidc/getoutbound?username=admin&password=admin&seq=1 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n\r\n\r\n"

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeGetoutboundRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

}

func TestSouthboundSetTimeRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"POST /eidc/setTime?username=admin&password=admin&seq=2 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 210\r\n\r\n" +
			`{"time":"2019-11-01T18:50:51-05:00","dstObservance":"observe on","dstStart":{"month":3,"weekInMonth":2,"dayOfWeek":7,"hour":2,"minute":0},"dstEnd":{"month":11,"weekInMonth":1,"dayOfWeek":7,"hour":2,"minute":0}}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeSetTimeRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

}

func TestSouthboundSetWebUserRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"POST /eidc/setwebuser?username=admin&password=admin&seq=3 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 40\r\n\r\n" +
			`{"Password":"0123456789","User":"admin"}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeSetWebUserRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

}

func TestSouthboundEnableEventsRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"GET /eidc/enableevents?username=admin&password=admin&seq=4 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n\r\n\r\n"

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeEnableEventsRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

}

func TestSouthboundGetPointStatusRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"POST /eidc/getPointStatus?username=admin&password=admin&seq=5 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 53\r\n\r\n" +
			`{"pointIds":[7,8,9,10,11,12,13,14,15,16,17,20,32,37]}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeGetPointStatusRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

	// todo: add message parsing feature to all similar tests
	r, err := msg.ParseGetPointStatusRequest()
	if err != nil {
		t.Fatal(err)
	}

	expectedPoints := []int{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 32, 37}
	var foundPoints []int
	for i := range r.PointIds {
		foundPoints = append(foundPoints, r.PointIds[i])
	}

	if len(expectedPoints) != len(foundPoints) {
		t.Fatal("discrepancy in point slice size")
	}

	for i := range expectedPoints {
		if expectedPoints[i] != foundPoints[i] {
			t.Fatalf("point instance %d mismatch: %d vs %d", i, expectedPoints[i], foundPoints[i])
		}
	}

}

func TestSouthboundHeartbeatRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"GET /eidc/heartbeat?username=admin&password=admin&seq=9 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n\r\n\r\n"

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeHeartbeatRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

}

func TestSouthboundEventAckRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"POST /eidc/eventack?username=admin&password=admin&seq=32 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 18\r\n\r\n" +
			`{"eventIds":[894]}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeEventAckRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}

}

func TestSouthboundDoor0x2fLockStatusRequest(t *testing.T) {
	testDir := Southbound
	testData :=
		"POST /eidc/door/lockstatus?username=admin&password=admin&seq=203 HTTP/1.1\r\n" +
			"Host: 192.168.6.40\r\n" +
			"User-Agent: eIDCListener\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 35\r\n\r\n" +
			`{"status":"Unlocked","duration":-1}`

	msg, err := ReadMsg([]byte(testData), testDir)
	if err != nil {
		t.Fatal(err)
	}

	result := msg.GetType()
	expected := MsgTypeDoor0x2fLockStatusRequest
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestReadMsg(t *testing.T) {
	testData := "POST /eidc/connected HTTP/1.1\r\n" +
		"Host: 11.22.33.44:18800\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 218\r\n" +
		"ServerKey: 0123456789abcdef\r\n" +
		"\r\n" +
		"{\"serialNumber\":\"0x000000012345\", \"firmwareVersion\":\"3.4.20\", \"ipAddress\":\"22.33.44.55\", \"macAddress\":\"00:14:E4:01:23:45\", \"siteKey\":\"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\", \"configurationKey\":\"\", \"cardFormat\":\"short\"}"
	direction := Southbound
	msg, err := ReadMsg([]byte(testData), direction)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Request == nil {
		t.Fatal("msg.Request should not be nil")
	}
	if msg.Response != nil {
		t.Fatal("msg.Response should be nil")
	}
	if msg.Direction() != direction {
		t.Fatal("wrong direction")
	}
}

func TestMessage_ParseEnableEventsResponse(t *testing.T) {
	testData := "HTTP/1.0 200 OK\r\n" +
		"Server: eIDC32 WebServer\r\n" +
		"Content-type: application/json\r\n" +
		"Content-Length:  37\r\n" +
		"Cache-Control: no-cache\r\n" +
		"\r\n" +
		"{\"result\":true, \"cmd\":\"ENABLEEVENTS\"}"
	msg, err := ReadMsg([]byte(testData), Northbound)
	if err != nil {
		t.Fatal(err)
	}
	_ = msg
	var result EIDCSimpleResponse
	err = json.Unmarshal(msg.Body, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Result != true {
		t.Fatalf("expected 'true', got %t", result.Result)
	}
	if result.Cmd != "ENABLEEVENTS" {
		t.Fatalf("expected 'true', got %s", result.Cmd)
	}
}
