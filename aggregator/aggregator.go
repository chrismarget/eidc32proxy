package aggregator

import (
	"github.com/chrismarget/eidc32proxy"
	"sync"
)

// An Aggregator learns about many sessions, subscribes to session events from
// each. It serves as the interface to an end-user display and messsage inject
// features.
type Aggregator struct {
	lock *sync.Mutex
	// never delete from this map. it's keyed by size.
	session       map[int]*eidc32proxy.Session
	saLock        *sync.Mutex
	sessionAlerts map[chan int]struct{}
}

// NewAggregator creates a new session/message aggregator. Pass it a channel
// that supplies new sessions from the server as they're created.
func NewAggregator(newSessChan chan *eidc32proxy.Session) Aggregator {
	a := Aggregator{
		lock:          &sync.Mutex{},
		session:       make(map[int]*eidc32proxy.Session),
		saLock:        &sync.Mutex{},
		sessionAlerts: make(map[chan int]struct{}),
	}
	go a.handleSessions(newSessChan)
	return a
}

func (o *Aggregator) handleSessions(newSessChan chan *eidc32proxy.Session) {
	for newSession := range newSessChan {
		// Add the session to the aggregator's map[int]Session
		o.lock.Lock()
		i := o.size()
		o.session[i] = newSession
		o.lock.Unlock()

		// Update subscribers about the new Session
		o.saLock.Lock()
		for c := range o.sessionAlerts {
			c <- i
		}
		o.saLock.Unlock()

	}
}

// Size returns the number of sessions known to the aggregator
func (o Aggregator) Size() int {
	o.lock.Lock()
	defer o.lock.Unlock()
	return o.size()
}

func (o Aggregator) size() int {
	return len(o.session)
}

// AddGarbate is a temporary hack to increase the size of the aggregator's session map
func (o Aggregator) AddGarbage() {
	o.lock.Lock()
	defer o.lock.Unlock()
	i := o.size()
	o.session[i] = nil
}

// GetSession returns the specified session
func (o Aggregator) GetSession(i int) *eidc32proxy.Session {
	o.lock.Lock()
	defer o.lock.Unlock()
	return o.session[i]
}

// SubscribeToSessionAlerts returns a channel on which subscribers learn the
// aggregator index (int) of sessions, and a function which ends the
// subscription. The channel starts by returning any existing index of any
// sessions which exist when the subscription is created. Callers must take
// care to call the function which ends the subscription.
func (o *Aggregator) SubscribeToSessionAlerts() (chan int, func()) {
	// create the subscriber's channel
	c := make(chan int)

	// add the subscriber's channel to the map of subscriber channels
	o.saLock.Lock()
	o.sessionAlerts[c] = struct{}{}
	o.saLock.Unlock()

	// send all existing session indexes
	defer func() {
		for i := range o.session {
			c <- i
		}
	}()

	return c, func() {
		o.saLock.Lock()
		defer o.saLock.Unlock()
		delete(o.sessionAlerts, c)
		close(c)
	}
}

type SessionErr struct {
	ID  int
	Err error
}
