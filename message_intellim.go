package eidc32proxy

import (
	"encoding/json"
	"net/http"
)

const (
	heartbeatRequestURI        = "/eidc/heartbeat"        // GET; no body; stray newline
	getOutboundRequestURI      = "/eidc/getoutbound"      // GET; no body; stray newline
	enableEventsRequestURI     = "/eidc/enableevents"     // GET; no body; stray newline
	setTimeRequestURI          = "/eidc/setTime"          // POST; body contains a SetTimeRequest
	setWebUserRequestURI       = "/eidc/setwebuser"       // POST; body contains a SetWebUserRequest
	getPointStatusRequestURI   = "/eidc/getPointStatus"   // POST; body contains a GetPointStatusRequest
	eventAckRequestURI         = "/eidc/eventack"         // POST; body contains a EventAckRequest
	doorLockStatusRequestURI   = "/eidc/door/lockstatus"  // POST; body contains a Door0x2fLockStatusRequest
	resetEventsRequestURI      = "/eidc/resetevents"      // GET; no body; stray newline
	clearPointsRequestURI      = "/eidc/clearPoints"      // GET; no body; stray newline
	addPointsRequestURI        = "/eidc/addPoints"        // POST; body contains a AddPointsRequest
	resetPointEngineRequestURI = "/eidc/resetPointEngine" // GET; no body; stray newline
	clearFormatsRequestURI     = "/eidc/clearformats"     // GET; no body; stray newline
	addFormatsRequestURI       = "/eidc/addFormats"       // POST; body contains a AddFormatsRequest
	clearSchedulesRequestURI   = "/eidc/clearSchedules"   // GET; no body; stray newline
	clearHolidaysRequestURI    = "/eidc/clearHolidays"    // GET; no body; stray newline
	addSchedulesRequestURI     = "/eidc/addSchedules"     // POST; body contains a // todo: Content-Length: 16\r\n\r\n{"Schedules":[]}HTTP/1.0 200 OK
	clearPrivilegesRequestURI  = "/eidc/clearPrivileges"  // GET; no body; stray newline
	addPrivilegesRequestURI    = "/eidc/addPrivileges"    // POST; body contains a AddPrivilegesRequest
	clearCardsRequestURI       = "/eidc/clearCards"       // GET; no body; stray newline
	addCardsRequestURI         = "/eidc/addCards"         // POST; body contains a AddCardsRequest
	setConfigKeyRequestURI     = "/eidc/setConfigKey"     // POST; body contains a SetConfigKeyRequest
	setDeviceIDRequestURI      = "/eidc/setDeviceID"      // POST; body contains a SetDeviceIDRequest
	setOutboundRequestURI      = "/eidc/setoutbound"      // POST; body contains a SetOutboundRequest
	downloadRequestURI         = "/eidc/download"         // POST; body contains software image (unzipped .img not web)
	reflashRequestURI          = "/eidc/reflash"          // GET; no body; stray newline
)

const (
	queryParamUsername = "username"
	queryParamPassword = "password"
)

type lockstatus uint8

const (
	Unlocked lockstatus = iota
	Locked
	Normal
)

type lockstatusString string

const (
	unlockedCmd lockstatusString = "Unlocked"
	lockedCmd   lockstatusString = "Locked"
	normalCmd   lockstatusString = "Normal"
	unknownCmd  lockstatusString = "unknown"
)

func (o lockstatus) String() string {
	switch o {
	case Unlocked:
		return string(unlockedCmd)
	case Locked:
		return string(lockedCmd)
	case Normal:
		return string(normalCmd)
	default:
		return string(unknownCmd)
	}
}

// Intelli-M response to EIDC's POST /eidc/connected
type ConnectedResponse struct {
	ServerKey string      `json:"serverKey"`
	Other     interface{} `json:"-"`
}

// Intelli-M POST /eidc/setTime
type SetTimeRequest struct {
	Time          string                `json:"time"`
	DstObservance string                `json:"dstObservence"`
	DstStart      SetTimeRequestDSTData `json:"dstStart"`
	DstEnd        SetTimeRequestDSTData `json:"dstEnd"`
	Other         interface{}           `json:"-"`
}

type SetTimeRequestDSTData struct {
	Month       int         `json:"month"`
	WeekInMonth int         `json:"weekInMonth"`
	DayOfWeek   int         `json:"dayOfWeek"`
	Hour        int         `json:"hour"`
	Minute      int         `json:"minute"`
	Other       interface{} `json:"-"`
}

// Intelli-M POST /eidc/setwebuser
type SetWebUserRequest struct {
	Password string      `json:"Password"`
	User     string      `json:"User"`
	Other    interface{} `json:"-"`
}

// Intelli-M GET /eidc/getPointStatus
type GetPointStatusRequest struct {
	PointIds []int       `json:"pointIds"`
	Other    interface{} `json:"-"`
}

// Intelli-M POST /eidc/eventack
type EventAckRequest struct {
	EventIds []int       `json:"eventIds"`
	Other    interface{} `json:"-"`
}

// Intelli-M POST /eidc/door/lockstatus
type Door0x2fLockStatusRequest struct {
	Status   string      `json:"status"`
	Duration int         `json:"duration"`
	Other    interface{} `json:"-"`
}

// Intelli-M POST /eidc/addPoints
type AddPointsRequest struct {
	NewPoints []NewPoint `json:"Points"`
	Other     interface{}
}

type NewPoint struct {
	Type         string `json:"Type"`
	Index        int    `json:"Index"`
	RecordInfo   int    `json:"RecordInfo"`
	DeviceID     int    `json:"DeviceId"`
	PointId      int    `json:"PointId"`
	PointRefNo   int    `json:"PointRefNo"`
	PointDriver  int    `json:"PointDriver"`
	IPointFlag   int    `json:"IPointFlag"`
	IPointStatus int    `json:"IPointStatus"`
	IPointTick   int    `json:"IPointTick"`
}

// Intelli-M POST /eidc/addSchedules
type AddSchedulesRequest struct {
	Schedules []Schedule `json:"Schedules"`
}

type Schedule struct {
	// todo: We've never seen one of these yet
}

// Intelli-M POST /eidc/addPrivileges
type AddPrivilegesRequest struct {
	StartIndex int            `json:"StartIndex"`
	Privileges []NewPrivilege `json:"Privileges"`
	Other      interface{}
}

type NewPrivilege struct {
	ScheduleIDs []int  `json:"ScheduleIds"`
	FloorMask   []int  `json:"FloorMask"`
	Description string `json:"Description"`
}

// Intelli-M POST /eidc/addCards
type AddCardsRequest struct {
	CardHolders []CardHolder `json:"CardHolders"`
	Other       interface{}
}

type CardHolder struct {
	PinCode        string `json:"PinCode"`
	SiteCode       int    `json:"SiteCode"`
	CardCode       int    `json:"CardCode"`
	StrCardCode    string `json:"StrCardCode"`
	ActivationDate string `json:"ActivationDate"`
	ExpirationDate string `json:"ExpirationDate"`
	InGroup        int    `json:"InGroup"`
	OutGroup       int    `json:"OutGroup"`
	FirstIn        int    `json:"FirstIn"`
	ID             int    `json:"Id"`
	Description    string `json:"Description"`
}

// Intelli-M POST /eidc/setConfigKey
type SetConfigKeyRequest struct {
	ConfigurationKey string `json:"ConfigurationKey"`
}

// Intelli-M POST /eidc/setDeviceID
type SetDeviceIDRequest struct {
	DeviceID int `json:"deviceID"`
}

// Intelli-M POST /eidc/setoutbound
type SetOutboundRequest struct {
	SiteKey                string      `json:"siteKey"`
	PrimaryHostAddress     string      `json:"primaryHostAddress"`
	PrimaryPort            int         `json:"primaryPort"`
	SecondaryHostAddress   string      `json:"secondaryHostAddress"`
	SecondaryPort          int         `json:"secondaryPort"`
	PrimarySsl             int         `json:"primarySsl"`
	SecondarySsl           int         `json:"secondarySsl"`
	RetryInterval          int         `json:"retryInterval"`
	MaxRandomRetryInterval int         `json:"maxRandomRetryInterval"`
	Other                  interface{} `json:"-"`
}

func (o Message) getSouthboundMsgType() MsgType {
	switch {
	case o.Request != nil:
		return o.getSouthboundRequestType()
	case o.Response != nil:
		return o.getSouthboundResponseType()
	}
	return MsgTypeUnknown
}

func (o Message) getSouthboundRequestType() MsgType {
	switch o.Request.Method {
	case http.MethodGet:
		switch o.Request.URL.Path {
		case heartbeatRequestURI:
			return MsgTypeHeartbeatRequest
		case getOutboundRequestURI:
			return MsgTypeGetoutboundRequest
		case enableEventsRequestURI:
			return MsgTypeEnableEventsRequest
		case resetEventsRequestURI:
			return MsgTypeResetEventsRequest
		case clearPointsRequestURI:
			return MsgTypeClearPointsRequest
		case resetPointEngineRequestURI:
			return MsgTypeResetPointEngineRequest
		case clearFormatsRequestURI:
			return MsgTypeClearPointsRequest
		case clearSchedulesRequestURI:
			return MsgTypeClearSchedulesRequest
		case clearHolidaysRequestURI:
			return MsgTypeClearHolidaysRequest
		case clearPrivilegesRequestURI:
			return MsgTypeClearPrivilegesRequest
		case clearCardsRequestURI:
			return MsgTypeClearCardsRequest
		case reflashRequestURI:
			return MsgTypeReflashRequest
		default:
			return MsgTypeUnknown
		}
	case http.MethodPost:
		switch o.Request.URL.Path {
		case setTimeRequestURI:
			return MsgTypeSetTimeRequest
		case setWebUserRequestURI:
			return MsgTypeSetWebUserRequest
		case getPointStatusRequestURI:
			return MsgTypeGetPointStatusRequest
		case eventAckRequestURI:
			return MsgTypeEventAckRequest
		case doorLockStatusRequestURI:
			return MsgTypeDoor0x2fLockStatusRequest
		case setOutboundRequestURI:
			return MsgTypeSetOutboundRequest
		case addPointsRequestURI:
			return MsgTypeAddPointsRequest
		case addFormatsRequestURI:
			return MsgTypeAddFormatsRequest
		case addPrivilegesRequestURI:
			return MsgTypeAddPrivilegesRequest
		case addCardsRequestURI:
			return MsgTypeAddCardsRequest
		case setConfigKeyRequestURI:
			return MsgTypeSetConfigKeyRequest
		case setDeviceIDRequestURI:
			return MsgTypeSetDeviceIDRequest
		case addSchedulesRequestURI:
			return MsgTypeAddSchedulesRequest
		case downloadRequestURI:
			return MsgTypeDownloadRequest
		default:
			return MsgTypeUnknown
		}
	default:
		return MsgTypeUnknown
	}
}

func (o Message) getSouthboundResponseType() MsgType {
	if o.Response.Status != ok200 {
		return MsgTypeUnknown
	}
	if o.contentType() != ApplicationJSON {
		return MsgTypeUnknown
	}

	var result ConnectedResponse
	err := json.Unmarshal(o.Body, &result)
	if err != nil {
		return MsgTypeUnknown
	}
	if result.ServerKey == "" {
		return MsgTypeUnknown
	}

	return MsgTypeConnectedResponse
}

func (o Message) ParseConnectedResponse() (ConnectedResponse, error) {
	var result ConnectedResponse
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseSetOutboundRequest() (SetOutboundRequest, error) {
	var result SetOutboundRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseSetTimeRequest() (SetTimeRequest, error) {
	var result SetTimeRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseSetWebUserRequest() (SetWebUserRequest, error) {
	var result SetWebUserRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseGetPointStatusRequest() (GetPointStatusRequest, error) {
	var result GetPointStatusRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseEventAckRequest() (EventAckRequest, error) {
	var result EventAckRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseDoor0x2fLockStatusRequest() (Door0x2fLockStatusRequest, error) {
	var result Door0x2fLockStatusRequest
	err := json.Unmarshal(o.Body, &result)
	return result, err
}

func (o Message) ParseDownloadRequest() []byte {
	return o.Body
}
