package eidc32proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
)

const (
	ua                        = "User-Agent"
	ok200                     = "200 OK"
	contentType               = "content-type"
	ApplicationJSON           = "application/json"
	Northbound      Direction = true
	Southbound      Direction = false
)

const (
	MsgTypeUnknown                    MsgType = iota
	MsgTypeConnectedRequest                   // Northbound via POST
	MsgTypeConnectedResponse                  // Southbound
	MsgTypeGetoutboundRequest                 // Southbound via GET
	MsgTypeGetoutboundResponse                // Northbound
	MsgTypeGetPointStatusRequest              // Southbound via POST
	MsgTypeGetPointStatusResponse             // Northbound
	MsgTypeSetTimeRequest                     // Southbound via POST
	MsgTypeSetTimeResponse                    // Northbound
	MsgTypePointStatusRequest                 // Northbound via POST (no response)
	MsgTypeEventRequest                       // Northbound via POST (no response)
	MsgTypeDoor0x2fLockStatusRequest          // Southbound via POST
	MsgTypeDoor0x2fLockStatusResponse         // Northbound
	MsgTypeEnableEventsRequest                // Southbound via GET
	MsgTypeEnableEventsResponse               // Northbound EIDCSimpleResponse
	MsgTypeEventAckRequest                    // Southbound via POST
	MsgTypeEventAckResponse                   // Northbound EIDCSimpleResponse
	MsgTypeHeartbeatRequest                   // Southbound via GET
	MsgTypeHeartbeatResponse                  // Northbound EIDCSimpleResponse
	MsgTypeSetWebUserRequest                  // Southbound via POST
	MsgTypeSetWebUserResponse                 // Northbound EIDCSimpleResponse
	MsgTypeSetOutboundRequest                 // Southbound via POST
	MsgTypeSetOutboundResponse                // Northbound EIDCSimpleResponse
	MsgTypeResetEventsRequest                 // Southbound via GET
	MsgTypeResetEventsResponse                // Northbound
	MsgTypeClearPointsRequest                 // Southbound via GET
	MsgTypeClearPointsResponse                // Northbound
	MsgTypeAddPointsRequest                   // Southbound via POST
	MsgTypeAddPointsResponse                  // Northbound
	MsgTypeResetPointEngineRequest            // Southbound via GET
	MsgTypeResetPointEngineResponse           // Northbound
	MsgTypeAddFormatsRequest                  // Southbound via POST
	MsgTypeAddFormatsResponse                 // Northbound
	MsgTypeAddPrivilegesRequest               // Southbound via POST
	MsgTypeAddPrivilegesResponse              // Northbound
	MsgTypeAddCardsRequest                    // Southbound via POST
	MsgTypeAddCardsResponse                   // Northbound
	MsgTypeSetConfigKeyRequest                // Southbound via POST
	MsgTypeSetConfigKeyResponse               // Northbound
	MsgTypeSetDeviceIDRequest                 // Southbound via POST
	MsgTypeSetDeviceIDResponse                // Northbound
	MsgTypeClearSchedulesRequest              // Southbound via GET
	MsgTypeClearSchedulesResponse             // Northbound
	MsgTypeClearHolidaysRequest               // Southbound via GET
	MsgTypeClearHolidaysResponse              // Northbound
	MsgTypeAddSchedulesRequest                // Southbound via POST
	MsgTypeAddSchedulesResponse               // Northbound
	MsgTypeClearPrivilegesRequest             // Southbound via GET
	MsgTypeClearPrivilegesResponse            // Northbound
	MsgTypeClearCardsRequest                  // Southbound via GET
	MsgTypeClearCardsResponse                 // Northbound
	MsgTypeDownloadRequest                    // Southbound via POST
	MsgTypeDownloadResponse                   // Northbound
	MsgTypeReflashRequest                     // Southbound via GET
	MsgTypeReflashResponse                    // Northbound
)

type MsgType int
type Direction bool
type Message struct {
	direction Direction
	Request   *http.Request
	Response  *http.Response
	Body      []byte
	Type      MsgType
	origBytes []byte
	Injected  bool
	Dropped   bool
	lock      *sync.Mutex
}

// Send sends a message in the passed session. It's really only safe to use with
// messages that don't provoke a response. Messages that *do* provoke a response
// should be sent using the session's Inject() method because it supports
// including manglers which can be used to intercept those responses.
func (o Message) Send(s *Session) {
	s.Inject(o, nil)
}

// ReadMsg parses a byte slice containing an entire HTTP message including
// headers and body. It also takes a direction. ReadMsg returns a *Message
// with appropriate fields populated. Note that the Message structure contains
// both *http.Request and *http.Response elements. Exactly one of these will be
// populated, depending on what's found in the []byte.
func ReadMsg(in []byte, dir Direction) (*Message, error) {
	var err error
	msg := &Message{
		direction: dir,
		origBytes: in,
		lock: &sync.Mutex{},
	}
	switch {
	case isRequest(in):
		msg.Request, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(in)))
		if err != nil {
			return msg, err
		}
		if msg.Request.ContentLength > 0 {
			msg.Body, err = ioutil.ReadAll(msg.Request.Body)
			if err != nil {
				return msg, err
			}
		}
	case isResponse(in):
		msg.Response, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(in)), nil)
		if err != nil {
			return msg, err
		}
		if msg.Response.ContentLength > 0 {
			msg.Body, err = ioutil.ReadAll(msg.Response.Body)
			if err != nil {
				return msg, err
			}
		}
	default:
		return msg, errors.New("data submitted to ReadMsg neither a request nor response")
	}
	msg.Type = msg.GetType()
	return msg, nil
}

// Marshal renders a message into bytes suitable for transmission
func (o Message) Marshal() ([]byte, error) {
	switch {
	case o.Request != nil:
		return o.marshalRequest()
	case o.Response != nil:
		return o.marshalResponse()
	default:
		return nil, errors.New("cannot Marshal message with neither request or response elements")
	}
}

func (o Message) marshalRequest() ([]byte, error) {
	o.lock.Lock()
	defer o.lock.Unlock()
	// Re-set the original user-agent string. If blank, we set
	// it blank. This stops GO from using its own value here.
	o.Request.Header.Set(ua, o.Request.Header.Get(ua))
	o.Request.Body = ioutil.NopCloser(bytes.NewReader(o.Body))
	out := bytes.Buffer{}
	err := o.Request.Write(&out)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (o Message) marshalResponse() ([]byte, error) {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.Response.Body = ioutil.NopCloser(bytes.NewReader(o.Body))
	out := bytes.Buffer{}
	err := o.Response.Write(&out)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (o Direction) String() string {
	switch o {
	case true:
		return "Northbound"
	default:
		return "Southbound"
	}
}

func (o Message) GetType() MsgType {
	if o.Type != 0 {
		return o.Type
	}
	switch o.direction {
	case Northbound:
		return o.getNorthboundType()
	case Southbound:
		return o.getSouthboundMsgType()
	}
	// This should never happen
	return o.Type
}

func (o Message) Direction() Direction {
	return o.direction
}

func (o MsgType) String() string {
	switch o {
	case MsgTypeConnectedRequest:
		return "Connected Request"
	case MsgTypeConnectedResponse:
		return "Connected Response"
	case MsgTypeGetoutboundRequest:
		return "Getoutbound Request"
	case MsgTypeGetoutboundResponse:
		return "Getoutbound Response"
	case MsgTypeGetPointStatusRequest:
		return "GetPointStatus Request"
	case MsgTypeGetPointStatusResponse:
		return "GetPointStatus Response"
	case MsgTypeSetTimeRequest:
		return "SetTime Request"
	case MsgTypeSetTimeResponse:
		return "SetTime Response"
	case MsgTypePointStatusRequest:
		return "PointStatus Request"
	case MsgTypeEventRequest:
		return "Event Request"
	case MsgTypeDoor0x2fLockStatusRequest:
		return "Door/LockStatus Request"
	case MsgTypeDoor0x2fLockStatusResponse:
		return "Door/LockStatus Response"
	case MsgTypeEnableEventsRequest:
		return "EnableEvents Request"
	case MsgTypeEnableEventsResponse:
		return "EnableEvents Response"
	case MsgTypeEventAckRequest:
		return "EventAck Request"
	case MsgTypeEventAckResponse:
		return "EventAck Response"
	case MsgTypeHeartbeatRequest:
		return "Heartbeat Request"
	case MsgTypeHeartbeatResponse:
		return "Heartbeat Response"
	case MsgTypeSetWebUserRequest:
		return "SetWebUser Request"
	case MsgTypeSetWebUserResponse:
		return "SetWebUser Response"
	case MsgTypeSetOutboundRequest:
		return "SetOutbound Request"
	case MsgTypeSetOutboundResponse:
		return "SetOutbound Response"
	case MsgTypeResetEventsRequest:
		return "ResetEvents Request"
	case MsgTypeResetEventsResponse:
		return "ResetEvents Response"
	case MsgTypeClearPointsRequest:
		return "ClearPoints Request"
	case MsgTypeClearPointsResponse:
		return "ClearPoints Response"
	case MsgTypeAddPointsRequest:
		return "AddPoints Request"
	case MsgTypeAddPointsResponse:
		return "AddPoints Response"
	case MsgTypeResetPointEngineRequest:
		return "ResetPointEngine Request"
	case MsgTypeResetPointEngineResponse:
		return "ResetPointEngine Response"
	case MsgTypeAddFormatsRequest:
		return "AddFormats Request"
	case MsgTypeAddFormatsResponse:
		return "AddFormats Response"
	case MsgTypeAddPrivilegesRequest:
		return "AddPrivileges Request"
	case MsgTypeAddPrivilegesResponse:
		return "AddPrivileges Response"
	case MsgTypeAddCardsRequest:
		return "AddCards Request"
	case MsgTypeAddCardsResponse:
		return "AddCards Response"
	case MsgTypeSetConfigKeyRequest:
		return "SetConfigKey Request"
	case MsgTypeSetConfigKeyResponse:
		return "SetConfigKey Response"
	case MsgTypeSetDeviceIDRequest:
		return "SetDeviceID Request"
	case MsgTypeSetDeviceIDResponse:
		return "SetDeviceID Response"
	case MsgTypeClearSchedulesRequest:
		return "ClearSchedules Request"
	case MsgTypeClearSchedulesResponse:
		return "ClearSchedules Response"
	case MsgTypeClearHolidaysRequest:
		return "ClearHolidays Request"
	case MsgTypeClearHolidaysResponse:
		return "ClearHolidays Response"
	case MsgTypeAddSchedulesRequest:
		return "AddSchedules Request"
	case MsgTypeAddSchedulesResponse:
		return "AddSchedules Response"
	case MsgTypeClearPrivilegesRequest:
		return "ClearPrivileges Request"
	case MsgTypeClearPrivilegesResponse:
		return "ClearPrivileges Response"
	case MsgTypeClearCardsRequest:
		return "ClearCards Request"
	case MsgTypeClearCardsResponse:
		return "ClearCards Response"
	case MsgTypeDownloadRequest:
		return "Download Request"
	case MsgTypeDownloadResponse:
		return "Download Response"
	case MsgTypeReflashRequest:
		return "Reflash Request"
	case MsgTypeReflashResponse:
		return "Reflash Response"
	default:
		return fmt.Sprintf("Event type %d has no string value", o)
	}

}

func (o Message) contentType() string {
	switch {
	case o.Request != nil:
		return o.Request.Header.Get(contentType)
	case o.Response != nil:
		return o.Response.Header.Get(contentType)
	}
	return ""
}

func (o Message) OrigBytes() []byte {
	return o.origBytes
}

func (o Message) String() (string, error) {
	b, err := o.Marshal()
	if err != nil {
		return "", err
	}
	_ = b

	i, err := impersonate(b, o.direction)
	if err != nil {
		return "", err
	}

	return string(i), nil
}

func (o Message) PrintableLines() ([]string, error){
	now := time.Now().Format("01/02 15:04:05")

	str, err := o.String()
	if err != nil {
		return nil, err
	}

	// make carriage returns and newlines printable
	str = strings.ReplaceAll((str), "\r", "\\r")
	str = strings.ReplaceAll((str), "\n", "\\n\n")

	lines := strings.Split(str, "\n")
	for i, l := range lines {
		switch o.direction {
		case Northbound:
			switch {
			case o.Injected:
				lines[i] = fmt.Sprintf("%s\t%s\n", aurora.White(now), aurora.Italic(aurora.Red(l)))
			case o.Dropped:
				lines[i] = fmt.Sprintf("%s\t%s\n", aurora.White(now), aurora.BgRed(l))
			default:
				lines[i] = fmt.Sprintf("%s\t%s\n", aurora.White(now), aurora.Red(l))
			}
		case Southbound:
			switch {
			case o.Injected:
				lines[i] = fmt.Sprintf("%s\t%s\n", aurora.White(now), aurora.Italic(aurora.Blue(l)))
			case o.Dropped:
				lines[i] = fmt.Sprintf("%s\t%s\n", aurora.White(now), aurora.BgBlue(l))
			default:
				lines[i] = fmt.Sprintf("%s\t%s\n", aurora.White(now), aurora.Blue(l))
			}
		}
	}
	return lines, nil
}