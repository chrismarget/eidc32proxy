package display

type Display interface {
	// Run the display.
	Run()

	// ErrChan returns a channel on which the display will send errors
	ErrChan() chan error

	// Stop stops the display
	Stop()
}
