package display

import (
	"errors"
	"fmt"
	"github.com/chrismarget/eidc32proxy"
	"github.com/chrismarget/eidc32proxy/aggregator"
	"github.com/logrusorgru/aurora"
	"strings"
	"time"
)

type DumpFirstDisplay struct {
	agg      aggregator.Aggregator
	errChan  chan error
	stopChan chan struct{}
	running  bool
}

// Run starts the display application running. It does not return except on
// user exit or fatal error.
func (o *DumpFirstDisplay) Run() {
	// don't start twice
	if o.running {
		o.errChan <- errors.New("display already running")
	} else {
		o.running = true
	}

	// end main by nil-ing the error channel
	// todo: does this work?
	defer func() {
		o.errChan <- nil
	}()

	sessIdx := o.firstSessionIndex()
	session := o.agg.GetSession(sessIdx)
	sessErrChan := session.SubscribeErr()
	msgChan, unSub := session.Pager.Subscribe(eidc32proxy.SubInfo{})

	session.BeginRelaying()

	for {
		select {
		case msg := <-msgChan:
			printMsg(msg)
		case err := <-sessErrChan:
			o.errChan <- err
		case <-o.stopChan:
			unSub()
			return
		}
	}
}

func printMsg(msg eidc32proxy.Message) {
	now := time.Now().Format("01/02 15:04:05")
	// replace \r\n characters with printable \r\n, plus an actual newline
	msgText := strings.ReplaceAll(string(msg.OrigBytes()),
		"\r\n", "\\r\\n\n")
	// split on those newlines we just added
	msgLines := strings.Split(msgText, "\n")
	if len(msgLines[len(msgLines)-1]) == 0 { // Last slice index empty string?
		msgLines = msgLines[:len(msgLines)-2] // Trim off the last slice entry.
	}
	switch msg.Direction() {
	case eidc32proxy.Northbound:
		for _, s := range msgLines {
			if s != "" {
				fmt.Printf("%s\t%s\n", aurora.White(now), aurora.Red(s))
			}
		}
	case eidc32proxy.Southbound:
		for _, s := range msgLines {
			if s != "" {
				fmt.Printf("%s\t%s\n", aurora.White(now), aurora.Blue(s))
			}
		}
	}
}

//todo: this. shit.
func (o *DumpFirstDisplay) ErrChan() chan error {
	var errChan chan error
	return errChan
}

func (o *DumpFirstDisplay) Stop() {

}

// NewDumpFirstDisplay returns an implementation of Display that dumps the
// first eIDC32 session to the terminal. The output is color coded:
//  - upstream messages in red
//  - downstream messages in blue
//  - errors and timestamps in white
// Line terminators 0x0A and 0x0D are rewritten as \n and \r, and line breaks
// are inserted at these points for readability.
func NewDumpFirstDisplay(sessChan chan *eidc32proxy.Session) *DumpFirstDisplay {
	var ntd DumpFirstDisplay
	ntd.errChan = make(chan error)
	ntd.stopChan = make(chan struct{})
	ntd.agg = aggregator.NewAggregator(sessChan)
	return &ntd
}

func (o DumpFirstDisplay) firstSessionIndex() int {
	// subscribe to session index info
	newSessChan, end := o.agg.SubscribeToSessionAlerts()

	// Wait for first session index, then drop our subscription.
	i := <-newSessChan // get the first session index
	end()              // unsubscribe from new session info

	// Now that we've unsubscribed, the channel should close. Drain any
	// remaining indexes that may be there so we don't block the writer.
	defer func() {
		for i := range newSessChan {
			sess := o.agg.GetSession(i)
			sess.BeginRelaying()
		}
	}()

	return i
}
