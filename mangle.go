package eidc32proxy

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
)

type (
	MangleResult uint8
	Mangler      interface {
		Mangle(*Message) (MangleResult, error)
	}
)

const (
	serverRequestSequenceParam              = "seq"
	ManglerDone                MangleResult = 1 << 0
	ManglerDrop                MangleResult = 1 << 1
	ManglerErr                 MangleResult = 1 << 2
	ManglerSuccess             MangleResult = 1 << 3
	ManglerNoop                MangleResult = 1 << 4
)

type seqMangler struct {
	lastSeq int
	log     bool
}

func (o *seqMangler) Mangle(msg *Message) (MangleResult, error) {
	// reasons to bail early
	switch {
	case msg.Direction() != Southbound:
		return ManglerNoop, nil
	case msg.Request == nil:
		return ManglerNoop, nil
	}

	// extract the whole URL. Something like:
	// /eidc/heartbeat?username=admin&password=admin&seq=9
	u, err := url.Parse(msg.Request.URL.String())
	if err != nil {
		return ManglerErr, err
	}

	// values maps keys (username, password, seq) to slices of
	// strings (in case a key appears more than once, i guess?)
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ManglerErr, err
	}

	// extract the first occurence of "seq", convert it to int
	seqStr := values.Get(serverRequestSequenceParam)
	if seqStr == "" {
		return ManglerNoop, nil
	}
	seqIn, err := strconv.Atoi(seqStr)
	if err != nil {
		return ManglerErr, err
	}

	// at this point we can be confident that a sequenced command
	// has arrived. No matter what, this message is getting sent,
	// so lastSeq will need to be incremented. Do that now.
	o.lastSeq++

	// bail if this message is *already* sequenced correctly
	if o.lastSeq == seqIn {
		if o.log {
			log.Printf("Sequence %d okay", seqIn)
		}
		return ManglerNoop, nil
	}

	if o.log {
		log.Printf("Sequence %d set to %d", seqIn, o.lastSeq)
	}

	// rebuild the URL with the new value before returning.
	values.Set(serverRequestSequenceParam, strconv.Itoa(o.lastSeq))
	u.RawQuery = values.Encode()
	msg.Request.URL = u

	return ManglerSuccess, nil
}

type DropMessageByType struct {
	DropType  MsgType
	Remaining int
}

func (o *DropMessageByType) Mangle(msg *Message) (MangleResult, error) {
	if msg.Type == o.DropType {
		log.Println("Dropping message")
		o.Remaining--
		var result MangleResult
		result = result & ManglerSuccess
		result = result & ManglerDrop
		if o.Remaining < 1 {
			result = result & ManglerDone
		}
		return result, nil
	}
	return ManglerNoop, nil
}

type PrintMangler struct{}

func (o PrintMangler) Mangle(msg *Message) (MangleResult, error) {
	log.Printf("%s %s message", msg.direction.String(), msg.Type.String())
	switch msg.Type {
	case MsgTypeEventRequest:
		eventReq, err := msg.ParseEventRequest()
		if err != nil {
			return ManglerNoop, err
		}
		log.Printf("  event type %s", eventReq.EventType)
	}
	return ManglerNoop, nil
}

// dropEidcResponse is a mangler that drops a single instance of an eIDC32 WebServer
// HTTP response message. These messages come in response to IntelliM commands, and
// include an EIDCSimpleResponse{} or EIDCBodyResponse{} as payload.
// It's a one-shot mangler, so it removes itself after dropping a single message.
// msgType is used to match the message we'd like to suppress.
// log controls whether we print to stderr.
type dropEidcResponse struct {
	log     bool
	msgType MsgType
}

func (o dropEidcResponse) Mangle(msg *Message) (MangleResult, error) {
	if msg.direction != Northbound {
		return ManglerNoop, nil
	}

	if msg.Response == nil {
		return ManglerNoop, nil
	}

	if msg.Type != o.msgType {
		return ManglerNoop, nil
	}

	if o.log {
		log.Printf("Dropping %s response, this mangler is done.", string(msg.Body))
	}

	return ManglerDrop | ManglerDone, nil
}

// DropEidcEvent mangler suppresses northbound eIDC32 event messages.
// Doing so requres 3 distinct operations:
//  1) Match the event message, suppress it so it doesn't reach the server.
//  2) Generate a fake server ACK message (POST event ID to /eidc/eventack)
//  3) Match the eIDC HTTP response to the POST above, suppres it.
// EventType, OnlyBuffered and OnlyLive are filters used to select the event.
// FilterFunc() is optional, can be used for more granular event filtering. Return
// true to indicate whether an event should be suppressed.
// OneShot indicates the mangler should remove itself after the first match.
// Session is required becase we can't synthesize server responses without
// API credentials found in the Session structure.
// PostFunc() is optional, will be run after dropping the matching event.
type DropEidcEvent struct {
	EventType    EventType
	OnlyBuffered bool
	OnlyLive     bool
	OneShot      bool
	FilterFunc   func(event *EventRequest) bool
	PostFunc     func(session *Session) error
	Session      *Session
}

func (o DropEidcEvent) Mangle(msg *Message) (MangleResult, error) {
	// Session data is required

	if o.Session == nil {
		return ManglerNoop, fmt.Errorf("cannot drop eidc event without session info")
	}

	// ignore messages that aren't northbound event requests
	if msg.direction != Northbound {
		return ManglerNoop, nil
	}

	if msg.Type != MsgTypeEventRequest {
		return ManglerNoop, nil
	}

	// extract the event
	event, err := msg.ParseEventRequest()
	if err != nil {
		return ManglerNoop | ManglerErr, err
	}

	// check for mandatory buffered (or not) event types
	if o.OnlyBuffered && event.EventType&BufferedEventFlag != BufferedEventFlag {
		return ManglerNoop, nil
	}
	if o.OnlyLive && event.EventType&BufferedEventFlag != 0 {
		return ManglerNoop, nil
	}

	// strip the buffered event flag
	event.EventType = event.EventType & ^BufferedEventFlag

	// check for the required event type (if any)
	if o.EventType != 0 && event.EventType != o.EventType {
		return ManglerNoop, nil
	}

	// run FilterFunc if it exists
	if o.FilterFunc != nil {
		dropIt := o.FilterFunc(&event)
		if !dropIt {
			return ManglerNoop, nil
		}
	}

	eventAckRequest, err := NewEventAckMsg(o.Session.apiCreds.username, o.Session.apiCreds.password, event.EventID)
	if err != nil {
		return ManglerNoop, err
	}

	dropMangler := dropEidcResponse{
		log:     true,
		msgType: MsgTypeEventAckResponse,
	}
	go o.Session.Inject(*eventAckRequest, []Mangler{dropMangler})

	result := ManglerDrop
	if o.OneShot {
		result = result | ManglerDone
	}
	if o.PostFunc != nil {
		err = o.PostFunc(o.Session)
	}
	return result, err
}

type DropEidcPointStatusRequest struct {
	point point
}

func (o DropEidcPointStatusRequest) Mangle(msg *Message) (MangleResult, error) {
	if msg.direction != Northbound {
		return ManglerNoop, nil
	}
	if msg.Type != MsgTypePointStatusRequest {
		return ManglerNoop, nil
	}
	psr, err := msg.ParsePointStatusRequest()
	if err != nil {
		return ManglerNoop, err
	}
	for _, p := range psr.Points {
		if p.PointID == int(o.point) {
			return ManglerDone | ManglerDrop, nil
		}
	}
	return ManglerNoop, nil
}
