package eidc32proxy

import (
	"sync"
	"time"
)

type SubMsgCat int // Subscription Message Category

func (o SubMsgCat) String() string {
	switch o {
	case SubMsgCatAny:
		return "Message Category 'Any'"
	case SubMsgCatAnyNB:
		return "Message Category 'Any Northbound'"
	case SubMsgCatAnyNBReq:
		return "Message Category 'Any Northbound Request'"
	case SubMsgCatAnyNBResp:
		return "Message Category 'Any Northbound Response'"
	case SubMsgCatAnySB:
		return "Message Category 'Any Southbound'"
	case SubMsgCatAnySBReq:
		return "Message Category 'Any Southbound Request'"
	case SubMsgCatAnySBResp:
		return "Message Category 'Any Southbound Response'"
	case SubMsgCatAnyReq:
		return "Message Category 'Any Request'"
	case SubMsgCatAnyResp:
		return "Message Category 'Any Response'"
	}
	return "Unknown Message Category"
}

const (
	SubMsgCatAny       SubMsgCat = iota // For subscriptions to all messages
	SubMsgCatAnyNB                      // For subscriptions to all Northbound messages
	SubMsgCatAnyNBReq                   // For subscriptions to all Northbound request messages
	SubMsgCatAnyNBResp                  // For subscriptions to all Northbound response messages
	SubMsgCatAnySB                      // For subscriptions to all Southbound messages
	SubMsgCatAnySBReq                   // For subscriptions to all Southbound request messages
	SubMsgCatAnySBResp                  // For subscriptions to all Southbound response messages
	SubMsgCatAnyReq                     // For subscriptions to all request messages
	SubMsgCatAnyResp                    // For subscriptions to all response messages
)

// SubInfo is provided with a MessagePager's SubscribeErr() method. It details
// the sort of message the subscriber is interested in receiving. It contains
// both a Category (for subscription to broad categories of messages) and a
// slice of MsgTypes (for subscription to specific message type(s)). The
// Category element is only considered if the []MsgType element is empty.
type SubInfo struct {
	Category SubMsgCat
	MsgTypes []MsgType
}

// NewMessagePager returns an implementation of MessagePager
func NewMessagePager() MessagePager {
	return &eidcMessagePager{
		mu:           &sync.Mutex{},
		timeout:      100 * time.Millisecond,
		typesToChans: make(map[MsgType]map[chan Message]struct{}),
		catsToChans:  make(map[SubMsgCat]map[chan Message]struct{}),
	}
}

// MessagePager is a simple interface for implementing a "pub-sub-like"
// message distribution model. Implementations of this interface will
// manage the distribution of messages to various interested parties.
//
// Callers may subscribe to messages by calling the desired method.
// Each listener method creates and returns two values:
//	- A receive-only chan
//	- A "unsub" function that ends the subscription and closes the channel
//
// Callers must take care to execute the "unsub" function when they are
// finished with the listener.
type MessagePager interface {
	// DistributeMessage distributes a new message to any subscribed
	// listeners. The inputs to this method are the data read directly
	// from the underlying network socket with very little parsing
	// or verification having been committed. The direction that the
	// message is heading is also provided.
	DistributeMessage(*Message)

	// Subscribe creates and returns a new Message listener. It is
	// typically invoked when socket data is successfully parsed
	// into a Message of the specified MsgType.
	//
	// Callers must execute the corresponding function returned
	// with the chan when they are finished with the chan.
	Subscribe(info SubInfo) (<-chan Message, func())
}

type eidcMessagePager struct {
	mu           *sync.Mutex
	timeout      time.Duration
	typesToChans map[MsgType]map[chan Message]struct{}
	catsToChans  map[SubMsgCat]map[chan Message]struct{}
}

func (o *eidcMessagePager) DistributeMessage(msg *Message) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Figure out what category matches this message
	var req, resp bool
	if msg.Request != nil {
		req = true
	}
	if msg.Response != nil {
		resp = true
	}
	dir := msg.Direction()
	var thisMsgCategory SubMsgCat
	switch dir {
	case Northbound:
		if req {
			thisMsgCategory = SubMsgCatAnyNBReq
		}
		if resp {
			thisMsgCategory = SubMsgCatAnyNBResp
		}
	case Southbound:
		if req {
			thisMsgCategory = SubMsgCatAnySBReq
		}
		if resp {
			thisMsgCategory = SubMsgCatAnySBResp
		}
	}

	sendTo := func(c chan Message) {
		timer := time.NewTimer(o.timeout)
		select {
		case c <- *msg:
			timer.Stop()
		case <-timer.C:
		}
	}

	// Send message to all message category channels
	for c := range o.catsToChans[thisMsgCategory] {
		sendTo(c)
	}

	// Send message to all type-specific channels
	for c := range o.typesToChans[msg.GetType()] {
		sendTo(c)
	}
}

func (o *eidcMessagePager) Subscribe(info SubInfo) (<-chan Message, func()) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if len(info.MsgTypes) > 0 {
		return o.subscribeByType(info.MsgTypes)
	}
	return o.subscribeByCategory(info.Category)
}

func (o *eidcMessagePager) subscribeByType(msgTypes []MsgType) (<-chan Message, func()) {
	c := make(chan Message)
	for _, msgType := range msgTypes { // Loop over subscriber's message types
		// Create the map for this type of message if it doesn't already exist
		chanMapForThisType := o.typesToChans[msgType]
		if chanMapForThisType == nil {
			chanMapForThisType = make(map[chan Message]struct{})
			o.typesToChans[msgType] = chanMapForThisType
		}
		// Add the subscriber's channel to the map
		chanMapForThisType[c] = struct{}{}
	}

	// Create the unsubscribe function for this subscriber,
	// return it along with the subscriber's channel.
	return c, func() {
		o.mu.Lock()
		for _, msgType := range msgTypes { // Loop over subscriber's message types
			chanMapForThisType := o.typesToChans[msgType]
			delete(chanMapForThisType, c)
			if len(chanMapForThisType) == 0 {
				delete(o.typesToChans, msgType)
			}
		}
		o.mu.Unlock()
		close(c)
	}
}

func (o *eidcMessagePager) subscribeByCategory(requested SubMsgCat) (<-chan Message, func()) {
	var msgCats []SubMsgCat
	switch requested {
	case SubMsgCatAny:
		msgCats = []SubMsgCat{SubMsgCatAnyNBReq, SubMsgCatAnyNBResp,
			SubMsgCatAnySBReq, SubMsgCatAnySBResp}
	case SubMsgCatAnyNB:
		msgCats = []SubMsgCat{SubMsgCatAnyNBReq, SubMsgCatAnyNBResp}
	case SubMsgCatAnySB:
		msgCats = []SubMsgCat{SubMsgCatAnySBReq, SubMsgCatAnySBResp}
	case SubMsgCatAnyReq:
		msgCats = []SubMsgCat{SubMsgCatAnyNBReq, SubMsgCatAnySBReq}
	case SubMsgCatAnyResp:
		msgCats = []SubMsgCat{SubMsgCatAnyNBResp, SubMsgCatAnySBResp}
	default:
		msgCats = []SubMsgCat{requested}
	}
	c := make(chan Message)
	for _, msgCat := range msgCats { // Loop over subscriber's message categories
		// Create the map for this type of message if it doesn't already exist
		chanMapForThisCategory := o.catsToChans[msgCat]
		if chanMapForThisCategory == nil {
			chanMapForThisCategory = make(map[chan Message]struct{})
			o.catsToChans[msgCat] = chanMapForThisCategory
		}
		// Add the subscriber's channel to the map
		chanMapForThisCategory[c] = struct{}{}
	}

	// Create the unsubscribe function for this subscriber,
	// return it along with the subscriber's channel.
	return c, func() {
		o.mu.Lock()
		for _, msgCat := range msgCats { // Loop over subscriber's message categories
			chanMapForThisCategory := o.catsToChans[msgCat]
			delete(chanMapForThisCategory, c)
			if len(chanMapForThisCategory) == 0 {
				delete(o.catsToChans, msgCat)
			}
		}
		o.mu.Unlock()
		close(c)
	}
}
