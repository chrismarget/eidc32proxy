package display

import (
	"github.com/rivo/tview"
	"testing"
	"time"
)

func TestGetNext(t *testing.T) {
	var a, b, c int

	a = 0
	b = 0
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = 1
	b = 0
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = -1
	b = 0
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = 0
	b = 1
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = 1
	b = 1
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = -1
	b = 1
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = 0
	b = 2
	c = getNext(a, b, next)
	if c != 1 {
		t.Fatalf("should be one")
	}
	c = getNext(a, b, previous)
	if c != 1 {
		t.Fatalf("should be one")
	}

	a = 1
	b = 2
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 0 {
		t.Fatalf("should be zero")
	}

	a = -1
	b = 2
	c = getNext(a, b, next)
	if c != 0 {
		t.Fatalf("should be zero")
	}
	c = getNext(a, b, previous)
	if c != 1 {
		t.Fatalf("should be one")
	}
}

func TestHb(t *testing.T) {
	hb := heartBeat{
		tv: tview.NewTextView().SetTextAlign(tview.AlignCenter),
	}
	app := tview.NewApplication()
	go func() {
		for i := 1; i < 15; i++ {
			time.Sleep(250 * time.Millisecond)
			hb.beat(app, 0)
		}
		app.Stop()
	}()
	err := app.SetRoot(hb.tv, true).Run()
	if err != nil {
		t.Fatal(err)
	}
}
