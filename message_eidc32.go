package eidc32proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	ConnectedRequestURI   = "/eidc/connected"   // sent via POST; body contains a ConnectedRequest
	PointStatusRequestURI = "/eidc/pointStatus" // sent via POST; body contains a PointStatusRequest
)

// Various "CMD" strings used by an eIDC to respond to a command issued by
// IntelliM. Be advised that these strings do not correspond 1:1 with the
// strings used in IntelliM's messages to an eIDC.
//
// Note how IntelliM says 'setTime', and the eIDC responds with 'SETTIME' in
// the following transaction:
//
//	// IntelliM says:
//	POST /eidc/setTime?username=admin&password=admin&seq=2 HTTP/1.1
//	Host: 192.168.6.40
//	User-Agent: eIDCListener
//	Content-Type: application/json
//	Content-Length: 210
//
//	{"time":"2019-11-01T18:39:54-05:00",(...)}
//
//	// eIDC responds with:
//	HTTP/1.0 200 OK
//	Server: eIDC32 WebServer
//	Content-type: application/json
//	Content-Length:  32
//	Cache-Control: no-cache
//
//	{"result":true, "cmd":"SETTIME"}
const (
	Door0x2fLockStatusResponseCmd = "DOOR/LOCKSTATUS"  // sent as the "cmd" field in an EIDCBodyResponse (payload also includes a Door0x2fLockStatusResponse)
	EnableEventsResponseCmd       = "ENABLEEVENTS"     // sent as the "cmd" field in an EIDCSimpleResponse
	EventAckResponseCmd           = "EVENTACK"         // sent as the "cmd" field in an EIDCSimpleResponse
	GetoutboundResponseCmd        = "GETOUTBOUND"      // sent as the "cmd" field in an EIDCBodyResponse (payload also includes a GetOutboundResponse)
	GetPointStatusResponseCmd     = "GETPOINTSTATUS"   // sent as the "cmd" field in an EIDCSimpleResponse (followed by upstream POSTs to /eidc/pointStatus)
	HeartbeatResponseCmd          = "HEARTBEAT"        // sent as the "cmd" field in an EIDCSimpleResponse
	SetTimeResponseCmd            = "SETTIME"          // sent as the "cmd" field in an EIDCSimpleResponse
	SetWebUserResponseCmd         = "SETWEBUSER"       // sent as the "cmd" field in an EIDCSimpleResponse
	SetOutboundResponseCmd        = "SETOUTBOUND"      // sent as the "cmd" field in an EIDCSimpleResponse
	ResetEventsResponseCmd        = "RESETEVENTS"      // sent as the "cmd" field in an EIDCSimpleResponse
	ClearPointsResponseCmd        = "CLEARPOINTS"      // sent as the "cmd" field in an EIDCSimpleResponse
	ResetPointEngineResponseCmd   = "RESETPOINTENGINE" // sent as the "cmd" field in an EIDCSimpleResponse
	AddFormatsResponseCmd         = "ADDFORMATS"       // sent as the "cmd" field in an EIDCBodyResponse (payload also includes a AddFormatsResponse)
	ClearSchedulesResponseCmd     = "CLEARSCHEDULES"   // sent as the "cmd" field in an EIDCSimpleResponse
	AddSchedulesResponseCmd       = "ADDSCHEDULES"     // sent as the "cmd" field in an EIDCSimpleResponse
	ClearPrivilegesResponseCmd    = "CLEARPRIVILEGES"  // sent as the "cmd" field in an EIDCSimpleResponse
	AddPrivilegesResponseCmd      = "ADDPRIVILEGES"    // sent as the "cmd" field in an EIDCSimpleResponse
	ClearCardsResponseCmd         = "CLEARCARDS"       // sent as the "cmd" field in an EIDCSimpleResponse
	SetConfigKeyResponseCmd       = "SETCONFIGKEY"     // sent as the "cmd" field in an EIDCSimpleResponse
	ClearHolidaysResponseCmd      = "CLEARHOLIDAYS"    // sent as the "cmd" field in an EIDCSimpleResponse
	DownloadResponseCmd           = "DOWNLOAD"         // sent as the "cmd" field in an EIDCBodyResponse (payload also includes a DownloadResponse)
	ReflashResponseCmd            = "REFLASH"          // sent as the "cmd" field in an EIDCSimpleResponse
	SetDeviceIDResponseCmd        = "SETDEVICEID"      // sent as the "cmd" field in an EIDCSimpleResponse
	AddCardsResponseCmd           = "ADDCARDS"         // sent as the "cmd" field in an EIDCBodyResponse (payload also includes a AddCardsResponse)
	AddPointsResponseCmd          = "ADDPOINTS"        // sent as the "cmd" field in an EIDCSimpleResponse
	// Other response strings found in firmware image
	// ADDHOLIDAYS
	// APBRESET
	// CARD
	// CLEARFORMATS
	// DEFAULTCONFIG
	// DELETECARDS
	// DELETEFORMATS
	// DELETEHOLIDAYS
	// DELETEPOINTS
	// DELETEPRIVILEGES
	// DELETESCHEDULES
	// EVENT/RECEIVER
	// FILETEST
	// GETCARDFORMAT
	// GETCARDS
	// GETCONFIGKEY
	// GETDEVICEID
	// GETFORMATS
	// GETHOLIDAYS
	// GETOUTBOUNDSTATUS
	// GETPOINTS
	// GETPRIVILEGES
	// GETSCHEDULES
	// GETSITEKEY
	// GETTIME
	// GETWEBENABLE
	// HOSTEDMODE
	// POINTOVERRIDE
	// REBOOT
	// RESETDB
	// SCHEDMETRICS
	// SETCARDFORMAT
	// SETCONFIGKEY
	// SETFTPUSER
	// SETSITEKEY
	// SINGLEPOINTSTATUS
	// UPLOAD
	// VERSION
)

// ConnectedRequest is the payload of eIDC32's
//   POST /eidc/connected
// request from eIDC32 to server
type ConnectedRequest struct {
	SerialNumber     string      `json:"serialNumber"`
	FirmwareVersion  string      `json:"firmwareVersion"`
	IPAddress        string      `json:"ipAddress"`
	MacAddress       string      `json:"macAddress"`
	SiteKey          string      `json:"siteKey"`
	ConfigurationKey string      `json:"configurationKey"`
	CardFormat       string      `json:"cardFormat"`
	Other            interface{} `json:"-"`
}

// PointStatusRequest is a northbound HTTP request (POST) from an eIDC32 to
// IntelliM. It details the current and previous status of one or more
// "points" (inputs/outputs) on the eIDC32.
type PointStatusRequest struct {
	Time   string      `json:"time"`
	Points []Point     `json:"points"`
	Other  interface{} `json:"-"`
}

// Point structure details the status of a single eIDC32 "point" (input/output)
// This structure is usually included in a PointStatusRequest
type Point struct {
	PointID   int         `json:"pointId"`
	OldStatus int         `json:"oldStatus"`
	NewStatus int         `json:"newStatus"`
	Other     interface{} `json:"-"`
}

// EventRequest is northbound POST data from an eIDC32 to IntelliM indicating
// a status change of an eIDC32 "point" (input/output"
type EventRequest struct {
	EventID   int         `json:"eventId"`
	EventType EventType   `json:"eventType"`
	Time      int         `json:"time"`
	PointID   int         `json:"pointId"`
	NewStatus int         `json:"newStatus"`
	OldStatus int         `json:"oldStatus"`
	TriggerID int         `json:"triggerId"`
	SiteCode  int         `json:"siteCode"`
	CardCode  int         `json:"cardCode"`
	ApbZoneID int         `json:"apbZoneId"`
	Other     interface{} `json:"-"`
}

// EIDCSimpleResponse contains a northbound HTTP response message from an
// eIDC32 device. "Simple" responses merely echo the command in the request and
// include a "result" boolean.
type EIDCSimpleResponse struct {
	Cmd    string      `json:"cmd"`
	Result bool        `json:"result"`
	Other  interface{} `json:"-"`
}

// AddBody is used to build up eIDC32 "body" response messages from "simple"
// response messages.
func (o EIDCSimpleResponse) AddBody(jsonBodyRaw []byte) *EIDCBodyResponse {
	return &EIDCBodyResponse{
		Cmd:    o.Cmd,
		Result: o.Result,
		Body:   jsonBodyRaw,
	}
}

// EIDCBodyResponse contains a northbound HTTP response message fom an
// eIDC32 device. "Body" responses are like the EIDCSimpleResponse
// messages, but include additional JSON information in the "body" field.
// It looks like "result" will always be true if we get one of these
type EIDCBodyResponse struct {
	Cmd    string          `json:"cmd"`
	Result bool            `json:"result"`
	Body   json.RawMessage `json:"body"`
	Other  interface{}     `json:"-"`
}

// EIDCErrorsResponse contains a northbound HTTP response message fom an
// eIDC32 device. "Error" responses are like the EIDCSimpleResponse
// messages, but include additional JSON information in the "errors" field.
// It looks like "result" will always be false if we get one of these.
type EIDCErrorsResponse struct {
	Cmd    string          `json:"cmd"`
	Result bool            `json:"result"`
	Errors json.RawMessage `json:"errors"`
	Other  interface{}     `json:"-"`
}

// GetOutboundResponse is the "body" structure representing the northbound
// response from eIDC32 to an IntelliM's "getoutbound" request.
type GetOutboundResponse struct {
	SiteKey                string      `json:"siteKey"`
	PrimaryHostAddress     string      `json:"primaryHostAddress"`
	PrimaryPort            int         `json:"primaryPort"`
	SecondaryHostAddress   string      `json:"secondaryHostAddress"`
	SecondaryPort          int         `json:"secondaryPort"`
	PrimarySsl             int         `json:"primarySsl"`
	SecondarySsl           int         `json:"secondarySsl"`
	RetryInterval          int         `json:"retryInterval"`
	MaxRandomRetryInterval int         `json:"maxRandomRetryInterval"`
	Enabled                int         `json:"enabled"`
	Other                  interface{} `json:"-"`
}

// AddFormsatsResponse  is the "body" of a EIDCBodyResponse to
// Intelli-M's 'addFormats' command.
type AddFormatsResponse struct {
	FormatsAdded int `json:"formatsAdded"`
}

// AddcardsResponse  is the "body" of a EIDCBodyResponse to
// Intelli-M's 'addCards' command.
type AddCardsResponse struct {
	CardsAdded int `json:"cardsAdded"`
}

// Door0x2fLockStatusResponse is the "body" of a EIDCBodyResponse to
// Intelli-M's lockStatus command.
type Door0x2fLockStatusResponse struct {
	Status string      `json:"status"`
	Other  interface{} `json:"-"`
}

// Door0x2fLockStatusResponse is the "body" of a EIDCBodyResponse to
// Intelli-M's lockStatus command.
type DownloadResponse struct {
	FileSize int         `json:"fileSize"`
	Other    interface{} `json:"-"`
}

// isControllerLogin indicates whether an HTTP request is a login attempt from
// an eIDC32 to its controller software.
func isControllerLogin(r *http.Request) bool {
	switch {
	case r.Method != http.MethodPost:
		return false
	case r.URL.Path != ConnectedRequestURI:
		return false
	case r.ContentLength <= 0:
		return false
	default:
		return true
	}
}

// parseControllerLoginBytes looks an awful lot like ParseConnectedRequest().
// The main distinction is that this function runs against []byte peek()'ed from
// the input reader. We don't have a session up and running yet, let alone
// relays passing proper messages around, so this one has to run against []byte.
func parseControllerLoginBytes(in []byte) (ConnectedRequest, error) {
	var out ConnectedRequest
	err := json.Unmarshal(in, &out)
	return out, err
}

func (o Message) parseEIDCSimpleResponse() (EIDCSimpleResponse, error) {
	var result EIDCSimpleResponse
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) parseEIDCBodyResponse() (EIDCBodyResponse, error) {
	var result EIDCBodyResponse
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseConnectedRequest() (ConnectedRequest, error) {
	var result ConnectedRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseGetOutboundResponse() (GetOutboundResponse, error) {
	var result GetOutboundResponse
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParsePointStatusRequest() (PointStatusRequest, error) {
	var result PointStatusRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseEventRequest() (EventRequest, error) {
	var result EventRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseDoor0x2fLockStatusResponse() (Door0x2fLockStatusResponse, error) {
	var result Door0x2fLockStatusResponse
	var eidcBR EIDCBodyResponse
	eidcBR, err := o.parseEIDCBodyResponse()
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(eidcBR.Body, &result)
	return result, err
}

func (o Message) ParseAddFormatsResponse() (AddFormatsResponse, error) {
	var result AddFormatsResponse
	var eidcBR EIDCBodyResponse
	eidcBR, err := o.parseEIDCBodyResponse()
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(eidcBR.Body, &result)
	return result, err
}

func (o Message) ParseAddCardsResponse() (AddCardsResponse, error) {
	var result AddCardsResponse
	var eidcBR EIDCBodyResponse
	eidcBR, err := o.parseEIDCBodyResponse()
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(eidcBR.Body, &result)
	return result, err
}

func (o Message) ParseEnableEventsResponse() (bool, error) {
	result, err := o.parseEIDCSimpleResponse()
	if err != nil {
		return false, err
	}
	if result.Cmd != EnableEventsResponseCmd {
		return false, fmt.Errorf("unexpected Cmd value, expected %s, got %s",
			EnableEventsResponseCmd,
			result.Cmd,
		)
	}
	return result.Result, nil
}

func (o Message) ParseSetTimeResponse() (bool, error) {
	result, err := o.parseEIDCSimpleResponse()
	if err != nil {
		return false, err
	}
	if result.Cmd != SetTimeResponseCmd {
		return false, fmt.Errorf("unexpected Cmd value, expected %s, got %s",
			SetTimeResponseCmd,
			result.Cmd,
		)
	}
	return result.Result, nil
}

func (o Message) getNorthboundType() MsgType {
	switch {
	case o.Request != nil:
		return o.getNorthboundRequestType()
	case o.Response != nil:
		return o.getNorthboundResponseType()
	}
	return MsgTypeUnknown
}

func (o Message) getNorthboundRequestType() MsgType {
	switch o.Request.Method {
	case http.MethodGet:
		return MsgTypeUnknown
	case http.MethodPost:
		switch o.Request.URL.String() {
		case ConnectedRequestURI:
			return MsgTypeConnectedRequest
		case PointStatusRequestURI:
			return MsgTypePointStatusRequest
		case EventRequestURI:
			return MsgTypeEventRequest
		}
	}
	return MsgTypeUnknown
}

func (o Message) getNorthboundResponseType() MsgType {
	if o.Response.Status != ok200 {
		return MsgTypeUnknown
	}
	if o.contentType() != ApplicationJSON {
		return MsgTypeUnknown
	}

	// todo: test parsing simple responses with this code
	var result EIDCBodyResponse
	err := json.Unmarshal(o.Body, &result)
	if err != nil {
		return MsgTypeUnknown
	}

	switch result.Cmd {
	case Door0x2fLockStatusResponseCmd:
		return MsgTypeDoor0x2fLockStatusResponse
	case EnableEventsResponseCmd:
		return MsgTypeEnableEventsResponse
	case EventAckResponseCmd:
		return MsgTypeEventAckResponse
	case GetoutboundResponseCmd:
		return MsgTypeGetoutboundResponse
	case GetPointStatusResponseCmd:
		return MsgTypeGetPointStatusResponse
	case HeartbeatResponseCmd:
		return MsgTypeHeartbeatResponse
	case SetTimeResponseCmd:
		return MsgTypeSetTimeResponse
	case SetWebUserResponseCmd:
		return MsgTypeSetWebUserResponse
	case SetOutboundResponseCmd:
		return MsgTypeSetOutboundResponse
	case ResetEventsResponseCmd:
		return MsgTypeResetEventsResponse
	case ClearPointsResponseCmd:
		return MsgTypeClearPointsResponse
	case ResetPointEngineResponseCmd:
		return MsgTypeResetPointEngineResponse
	case AddFormatsResponseCmd:
		return MsgTypeAddFormatsResponse
	case ClearSchedulesResponseCmd:
		return MsgTypeClearSchedulesResponse
	case AddSchedulesResponseCmd:
		return MsgTypeAddSchedulesResponse
	case ClearPrivilegesResponseCmd:
		return MsgTypeClearPrivilegesResponse
	case AddPrivilegesResponseCmd:
		return MsgTypeAddPrivilegesResponse
	case ClearCardsResponseCmd:
		return MsgTypeClearCardsResponse
	case SetConfigKeyResponseCmd:
		return MsgTypeSetConfigKeyResponse
	case ClearHolidaysResponseCmd:
		return MsgTypeClearHolidaysResponse
	case DownloadResponseCmd:
		return MsgTypeDownloadResponse
	case ReflashResponseCmd:
		return MsgTypeReflashResponse
	case SetDeviceIDResponseCmd:
		return MsgTypeSetDeviceIDRequest
	case AddCardsResponseCmd:
		return MsgTypeAddCardsResponse
	case AddPointsResponseCmd:
		return MsgTypeAddPointsResponse
	default:
		return MsgTypeUnknown
	}
}

func (o ConnectedRequest) String() string {
	return fmt.Sprintf(""+ // <- empty string stops GoFmt making a mess of the lines below
		"Serial Number:     %s\n"+
		"Firmware Version:  %s\n"+
		"IP Address:        %s\n"+
		"MAC Address:       %s\n"+
		"Site Key:          %s\n"+
		"Configuration Key: %s\n"+
		"Card Format:       %s\n",
		o.SerialNumber,
		o.FirmwareVersion,
		o.IPAddress,
		o.MacAddress,
		o.SiteKey,
		o.ConfigurationKey,
		o.CardFormat,
	)
}
