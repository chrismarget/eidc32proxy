package display

import (
	"fmt"
	"github.com/chrismarget/eidc32proxy"
	"github.com/chrismarget/eidc32proxy/aggregator"
	"github.com/gdamore/tcell"
	"github.com/rivo/tview"
	"strconv"
	"strings"
	"time"
)

type nextType bool

const (
	durWidth                     = 18
	hBWidth                      = durWidth
	noCxnTitle1                  = "Waiting for first eIDC32 session..."
	titleXofYString              = "Connection %d/%d"
	eidcShortInfoString          = "S/N %s @ %s -> %s"
	upString                     = "[green]Up %s[white]"
	downString                   = "[red]Down %s (Up %s)[white]"
	next                nextType = true
	previous            nextType = false
)

var (
	bH = []byte{226, 153, 161} // unicode 2661 (black heart)
	wH = []byte{226, 153, 165} // unicode 2665 (white heart)
)

const (
	liDetails     string = "Connection"
	liCredentials string = "Credentials"
	liInject      string = "Inject"
	liKill        string = "Kill Session"
	liAbout       string = "About"
	liQuit        string = "Quit"
)

// ┌──────────────────────────────────────titleFlex───────────────────────────────────────┐
// │heartBeat(TextView)              titleXofY(TextView)                duration(TextView)│ <- titleLine1
// │                           eidcShortInfo(TextView)                                    │ <- titleLine2
// └──────────────────────────────────────────────────────────────────────────────────────┘
//  (invisible box)  ┌────────────────────────────────────────────────────────────────────┐
// (d) Connection    │                                                                    │
// (c) Credentials   │                                                                    │
// (i) Inject        │                                                                    │
// (k) Kill Session  │                                                                    │
// (q) Quit          │                                                                    │
//                   │                                                                    │
//                   │             this whole pane is RightFlex                           │
//                   │                                                                    │
//       ^           │                                                                    │
//       │           │                                                                    │
//  invisible box    │                                                                    │
//  and list are     │                                                                    │
//  both part of     │                                                                    │
//  LeftFlex         └────────────────────────────────────────────────────────────────────┘

type heartBeat struct {
	tv *tview.TextView
}

// beat causes the heartbeat indicator to change state
func (o *heartBeat) beat(app *tview.Application, i uint32) {
	go func() {
		updateText(app, o.tv, fmt.Sprintf(" %s %d", wH, i))
		time.Sleep(300 * time.Millisecond)
		updateText(app, o.tv, fmt.Sprintf(" %s %d", bH, i))
	}()
}

type titleXofY struct {
	tv *tview.TextView
}

// render updates the titleXofY object with a new descriptive string
func (o *titleXofY) render(app *tview.Application, x int, y int) {
	if y < 1 { // still waiting for first connection
		updateText(app, o.tv, noCxnTitle1)
	} else { // normal "Connection X/Y" message
		updateText(app, o.tv, fmt.Sprintf(titleXofYString, x+1, y))
	}
}

type duration struct {
	tv *tview.TextView
}

// update ticks the duration clock display
func (o duration) update(app *tview.Application, session *eidc32proxy.Session) {
	var result string
	if session.EndTime.IsZero() {
		upTime := time.Since(session.StartTime).Truncate(time.Second)
		result = fmt.Sprintf(upString, upTime.String())
	} else {
		upTime := session.EndTime.Sub(session.StartTime).Truncate(time.Second)
		downTime := time.Since(session.EndTime).Truncate(time.Second)
		result = fmt.Sprintf(downString, downTime.String(), upTime.String())
	}
	updateText(app, o.tv, result)
}

func (o duration) runForSession(a *tview.Application, s *eidc32proxy.Session) func() {
	stop := make(chan struct{})
	ticker := time.NewTicker(time.Second)
	go func() {
		for {
			select {
			case <-stop:
				ticker.Stop()
				updateText(a, o.tv, "")
			case <-ticker.C:
				//os.Stdout.Write([]byte{7})
				o.update(a, s)
			}
		}
	}()
	return func() {
		stop <- struct{}{}
	}
}

type eidcShortInfo struct {
	tv *tview.TextView
}

// render displays the eidc serial number and brief connection info
func (o eidcShortInfo) render(app *tview.Application, sess *eidc32proxy.Session) {
	snString := sess.LoginInfo.ConnectedReq.SerialNumber
	snInt, err := strconv.ParseInt(snString, 0, 64)
	if err != nil {
		snString = "<unknown>"
	} else {
		snString = strconv.Itoa(int(snInt))
	}
	eIDCIP := sess.LoginInfo.ConnectedReq.IPAddress
	obervedIP := strings.Split(sess.Mitm.ClientSide.Client, ":")[0]
	var printableIPstring string
	if eIDCIP == obervedIP {
		printableIPstring = eIDCIP
	} else {
		printableIPstring = fmt.Sprintf("%s (%s)", eIDCIP, obervedIP)
	}
	destination := sess.LoginInfo.Host
	result := fmt.Sprintf(eidcShortInfoString, snString, printableIPstring, destination)
	updateText(app, o.tv, result)
}

type rightFlex struct {
	flex *tview.Flex
}

// setContents replaces the contents of the flex. Use it to populate with
// text, forms, grids, etc... as needed.
func (o rightFlex) setContents(item tview.Primitive, focus bool) {
	o.flex.Clear()
	o.flex.AddItem(item, 0, 100, focus)
}

// TVDisplay is an implementation of Display using the rivo/tview library
type TVDisplay struct {
	aggregator        aggregator.Aggregator
	currentConnection int
	app               *tview.Application
	heartBeat         heartBeat
	titleXofY         titleXofY
	duration          duration
	eidcShortInfo     eidcShortInfo
	list              *tview.List
	rightFlex         rightFlex
	err               chan error
	newSess           chan int
	quitNewSess       func()
	clearDuration     func()
}

func (o *TVDisplay) createTitleLine1() *tview.Flex {
	o.heartBeat = heartBeat{
		tv: tview.NewTextView().SetTextAlign(tview.AlignLeft),
	}
	o.titleXofY = titleXofY{
		tv: tview.NewTextView().SetTextAlign(tview.AlignCenter),
	}
	o.duration = duration{
		tv: tview.NewTextView().SetTextAlign(tview.AlignRight).
			SetDynamicColors(true),
	}
	return tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(o.heartBeat.tv, hBWidth, 0, false).
		AddItem(o.titleXofY.tv, 0, 100, false).
		AddItem(o.duration.tv, durWidth, 0, false)
}

func (o *TVDisplay) createTitleLine2() *tview.TextView {
	o.eidcShortInfo = eidcShortInfo{
		tv: tview.NewTextView().SetTextAlign(tview.AlignCenter),
	}
	return o.eidcShortInfo.tv

}

func (o *TVDisplay) createTitleFlex() *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(o.createTitleLine1(), 0, 100, true).
		AddItem(o.createTitleLine2(), 0, 100, false)
	flex.Box.SetBorder(true)
	return flex
}

func (o *TVDisplay) createListBox() *tview.List {
	o.list = tview.NewList().ShowSecondaryText(false)
	o.list.AddItem(liDetails, "", 'd', nil)
	o.list.AddItem(liCredentials, "", 'c', nil)
	o.list.AddItem(liInject, "", 'i', nil)
	o.list.AddItem(liKill, "", 'k', nil)
	o.list.AddItem(liAbout, "", 'a', nil)
	o.list.AddItem(liQuit, "", 'q', func() { o.Stop() })
	return o.list
}

func (o *TVDisplay) createLeftFlex() *tview.Flex {
	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewBox().SetBorder(false), 1, 0, false).
		AddItem(o.createListBox(), 0, 100, true)
}

func (o *TVDisplay) createRightFlex() rightFlex {
	o.rightFlex.flex = tview.NewFlex()
	//tview.NewTextView().SetTextAlign(tview.AlignLeft)
	o.rightFlex.flex.Box.SetBorder(true)
	return o.rightFlex
}

func (o *TVDisplay) createBottomFlex() *tview.Flex {
	return tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(o.createLeftFlex(), 18, 0, true).
		AddItem(o.createRightFlex().flex, 0, 100, false)
}

func (o *TVDisplay) createMainFlex() *tview.Flex {
	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(o.createTitleFlex(), 4, 0, false).
		AddItem(o.createBottomFlex(), 0, 100, true)
}

func createApplication(mainFlex *tview.Flex) *tview.Application {
	return tview.NewApplication().SetRoot(mainFlex, true)
}

// NewTVDisplay returns an implementation of Display using rivo/tview
func NewTVDisplay(sessChan chan *eidc32proxy.Session) *TVDisplay {
	var d TVDisplay
	d.aggregator = aggregator.NewAggregator(sessChan)
	d.app = createApplication(d.createMainFlex())
	d.err = make(chan error)
	d.newSess, d.quitNewSess = d.aggregator.SubscribeToSessionAlerts()
	d.clearDuration = func() {}
	return &d
}

// ErrChan returns the TVDisplay's error channel
func (o TVDisplay) ErrChan() chan error {
	return o.err
}

// Stop stops the TVDisplay tview Application
func (o TVDisplay) Stop() {
	o.app.Stop()
}

func (o *TVDisplay) x(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyRight:
		o.currentConnection = getNext(o.currentConnection, o.aggregator.Size(), next)
	case tcell.KeyLeft:
		o.currentConnection = getNext(o.currentConnection, o.aggregator.Size(), previous)
	case tcell.KeyUp:
		o.aggregator.AddGarbage()
	}
	return event
}

func (o TVDisplay) waitForFirstConn() {
	o.titleXofY.render(o.app, o.currentConnection, o.aggregator.Size())
	for o.aggregator.Size() < 1 {
		time.Sleep(250 * time.Millisecond)
	}
}

func (o TVDisplay) updateTitle(i int) {
	o.titleXofY.render(o.app, i, o.aggregator.Size())         // line 1 of title bar
	o.eidcShortInfo.render(o.app, o.aggregator.GetSession(i)) // line 2 of title bar

}

func (o TVDisplay) runClock() {
	for {
		time.Sleep(250 * time.Millisecond)
		//updateText(o.app, o.rightFlex.flex, currentTimeString(false))
		o.titleXofY.render(o.app, o.currentConnection, o.aggregator.Size())
	}
}

func updateClock(app *tview.Application, clock *tview.TextView, twelvehour bool) {
	for {
		time.Sleep(100 * time.Millisecond)
		updateText(app, clock, currentTimeString(twelvehour))
	}
}

func messWithLargePane(app *tview.Application, rf rightFlex) {
	clock1 := tview.NewTextView().SetTextAlign(tview.AlignLeft)
	go updateClock(app, clock1, false)
	clock2 := tview.NewTextView().SetTextAlign(tview.AlignRight)
	go updateClock(app, clock2, true)

	go func() {
		for {
			rf.setContents(clock1, true)
			time.Sleep(3 * time.Second)
			rf.setContents(clock2, true)
			time.Sleep(3 * time.Second)
		}
	}()
}

// Run starts the TVDisplay's rivo/tview appliation
func (o TVDisplay) Run() {
	go func() {
		o.err <- o.app.Run()
	}()

	// Render "waiting" title text (0 of 0 connections)
	o.titleXofY.render(o.app, 0, 0)

	// Get, start, and display the first session.
	o.currentConnection = <-o.newSess
	o.aggregator.GetSession(o.currentConnection).BeginRelaying()
	o.switchTo(o.currentConnection)

	go messWithLargePane(o.app, o.rightFlex)

	hbSub := eidc32proxy.SubInfo{
		MsgTypes: []eidc32proxy.MsgType{eidc32proxy.MsgTypeHeartbeatResponse},
	}

	// loop forever
	for {
		hb, stopHb := o.aggregator.GetSession(o.currentConnection).Pager.Subscribe(hbSub)
		select {
		case new := <-o.newSess: // New session has connected
			o.titleXofY.render(o.app, o.currentConnection, o.aggregator.Size()) // fix title
			o.aggregator.GetSession(new).BeginRelaying()                        // start new session
		case <-hb: // heartbeat message
			o.heartBeat.beat(o.app, o.aggregator.GetSession(o.currentConnection).HeartBeats())
		}
		go stopHb()
	}

	//messWithLargePane(o.app, o.rightFlex)
	//o.app.SetFocus(o.list)
}

func updateText(app *tview.Application, tv *tview.TextView, s string) {
	app.QueueUpdateDraw(func() {
		tv.SetText(s)
	})
}

func currentTimeString(twelveHour bool) string {
	t := time.Now()
	if twelveHour == true {
		return fmt.Sprintf(t.Format(" Current time is \n 3:04:05 "))
	}
	return fmt.Sprintf(t.Format(" Current time is \n 15:04:05 "))
}

// next facilitates incrementing "x of n" displays. it deals strictly with
// zero-indexed things. Input and output value match slice indexing. Need to
// add one for pretty user output (to get "1 of 2" instead of "0 of 2")
func getNext(current int, outOf int, n nextType) int {
	// too few choices? Don't do math, just return the "outOf" size because
	// the only possibility is index 0.
	if outOf <= 1 {
		return 0
	}

	// current value out of range negative? Return the first or last possible
	// value, depending on whether the caller asked for 'next' or 'previous'
	if current < 0 {
		switch n {
		case next:
			return 0
		case previous:
			return outOf - 1
		}
	}

	// Starting point can't be less than zero now, but might go negative if the
	// caller asks us to decrement (previous). Adding outOf to the initial
	// value ensures it won't go negative in that case, and won't affect the
	// outcome.
	current += outOf

	if n == previous {
		return (current - 1) % outOf
	}
	return (current + 1) % outOf
}

type paneMgr struct {
	pane *tview.Flex
}

func (o TVDisplay) switchTo(i int) {
	o.updateTitle(i)
	o.clearDuration()
	o.clearDuration = o.duration.runForSession(o.app, o.aggregator.GetSession(i))
}
