package client

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/chrismarget/eidc32proxy"
)

func ConnectWithConfig(config ConnectionConfig) (*Client, error) {
	err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate connection config - %w", err)
	}

	raw, err := eidc32proxy.IntellimHTTPRequestBytes(&eidc32proxy.IntellimHTTPRequestData{
		URL:       config.URL.IntelliM,
		SubPath:   eidc32proxy.ConnectedRequestURI,
		Method:    http.MethodPost,
		ServerKey: config.ServerKey,
		Body:      &config.Request,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create intellim connected message - %w", err)
	}

	conn, err := eidc32proxy.ConnFuncForURL(config.URL.ConnectTo(), "tcp4")()
	if err != nil {
		return nil, err
	}

	client := UpgradeConnToClient(conn, config.Pager)

	if config.FirstWriteTimeout > 0 {
		err = client.SendRawWithin(raw, config.FirstWriteTimeout)
	} else {
		err = client.SendRaw(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to send connected message - %w", err)
	}

	if config.FirstReadTimeout > 0 {
		_, err := client.ReadWithin(config.FirstReadTimeout)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// ConnectionConfig configures a connection to an Intelli-M instance.
type ConnectionConfig struct {
	// URL is the IntellimURL to connect to.
	URL *IntellimURL

	// Pager is the MessagePager to use for handling
	// incoming messages from Intelli-M.
	Pager eidc32proxy.MessagePager

	// FirstWriteTimeout is the maximum amount of time to wait for
	// the first write to the underlying socket to succeed.
	FirstWriteTimeout time.Duration

	// FirstReadTimeout is the maximum amount of time to wait for
	// the first read from the underlying socket to succeed.
	FirstReadTimeout time.Duration

	// ServerKey is the server key to use.
	ServerKey string

	// Request is the ConnectedRequest body to write in the
	// very first message to Intelli-M.
	Request eidc32proxy.ConnectedRequest
}

func (o ConnectionConfig) Validate() error {
	if o.URL == nil {
		return fmt.Errorf("intellim url cannot be nil")
	} else if o.Pager == nil {
		return fmt.Errorf("message pager cannot be nil")
	}

	return nil
}

// IntellimURL represents the possible URLs of an Intelli-M instance,
// and provides helper methods for selecting the appropriate URL value when
// communicating with an Intelli-M. If a proxy is needed, then OptionalProxy
// should be set to a non-nil *url.URL. Otherwise, it can be left nil.
type IntellimURL struct {
	IntelliM      *url.URL
	OptionalProxy *url.URL
}

// ConnectTo returns the *url.URL that clients should initiate connections to.
// This method picks between the Intelli-M's actual URL and an optional proxy
// URL, returning the appropriate value.
func (o IntellimURL) ConnectTo() *url.URL {
	if o.OptionalProxy != nil {
		return o.OptionalProxy
	}

	return o.IntelliM
}

func UpgradeConnToClient(conn net.Conn, pager eidc32proxy.MessagePager) *Client {
	onRead := make(chan []byte, 1)
	errChan := make(chan error, 1)
	go func() {
		defer close(onRead)
		scanner := bufio.NewScanner(conn)
		scanner.Split(eidc32proxy.SplitHttpMsg)
		for scanner.Scan() {
			select {
			case onRead <- scanner.Bytes():
			default:
			}
			msg, err := eidc32proxy.ReadMsg(scanner.Bytes(), eidc32proxy.Southbound)
			if err != nil {
				// TODO: Maybe this should be a "class"
				//  of error, and not an automatic
				//  "kill the connection" error?
				errChan <- err
				return
			}
			pager.DistributeMessage(msg)
		}

		select {
		case errChan <- scanner.Err():
		default:
		}
	}()

	return &Client{
		conn:    conn,
		onRead:  onRead,
		pager:   pager,
		errChan: errChan,
	}
}

type Client struct {
	conn    net.Conn
	pager   eidc32proxy.MessagePager
	errChan <-chan error
	onRead  <-chan []byte
}

func (o *Client) OnConnClosed() <-chan error {
	return o.errChan
}

func (o *Client) Pager() eidc32proxy.MessagePager {
	return o.pager
}

func (o *Client) SendRaw(message []byte) error {
	_, err := o.conn.Write(message)
	return err
}

func (o *Client) SendRawWithin(message []byte, timeout time.Duration) error {
	err := o.conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return fmt.Errorf("failed to set conn write deadline - %w", err)
	}

	_, err = o.conn.Write(message)
	// Reset the write deadline to default value
	// (i.e., never timeout).
	o.conn.SetWriteDeadline(time.Time{})
	return err
}

func (o *Client) ReadWithin(timeout time.Duration) ([]byte, error) {
	timer := time.NewTimer(timeout)
	select {
	case raw, isOpen := <-o.onRead:
		timer.Stop()
		if isOpen {
			return raw, nil
		} else {
			return nil, fmt.Errorf("socket has been closed, and is no longer readable")
		}
	case <-timer.C:
		return nil, fmt.Errorf("failed to read from socket in allotted time (%s)", timeout.String())
	}
}

func (o *Client) Close() error {
	return o.conn.Close()
}

// SubscribeTo helps to subscribe to a MessagePager for several types of
// message types.
func SubscribeTo(pager eidc32proxy.MessagePager, msgTypes ...eidc32proxy.MsgType) ([]<-chan eidc32proxy.Message, []func()) {
	var chans []<-chan eidc32proxy.Message
	var unsubFns []func()

	for _, msgType := range msgTypes {
		c, unsub := pager.Subscribe(eidc32proxy.SubInfo{
			MsgTypes: []eidc32proxy.MsgType{
				msgType,
			},
		})

		chans = append(chans, c)
		unsubFns = append(unsubFns, unsub)
	}

	return chans, unsubFns
}

// TrueDat starts a go routine for each provided Message channel and attempts
// to automatically respond with a response whose 'result' field is set
// to 'true'. Any response failures (such as response serialization errors,
// or socket write errors) are written to the returned channel.
//
// Each go routine exits when the corresponding Message channel is closed.
func TrueDat(sendResponseFn func([]byte, eidc32proxy.MsgType) error, chans ...<-chan eidc32proxy.Message) <-chan error {
	errs := make(chan error, 1)
	onErrFn := func(err error) {
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case errs <- err:
			timer.Stop()
		case <-timer.C:
		}
	}

	for _, c := range chans {
		go func(c <-chan eidc32proxy.Message) {
			for incommingMsg := range c {
				var cmd string
				// TODO: The 'cmd' string should be a method
				//  on MsgType, or should be included in the
				//  Message struct somewhere.
				msgType := incommingMsg.GetType()
				switch msgType {
				case eidc32proxy.MsgTypeSetOutboundRequest:
					cmd = eidc32proxy.SetOutboundResponseCmd
				case eidc32proxy.MsgTypeResetEventsRequest:
					cmd = eidc32proxy.ResetEventsResponseCmd
				case eidc32proxy.MsgTypeEnableEventsRequest:
					cmd = eidc32proxy.EnableEventsResponseCmd
				case eidc32proxy.MsgTypeHeartbeatRequest:
					cmd = eidc32proxy.HeartbeatResponseCmd
				case eidc32proxy.MsgTypeSetWebUserRequest:
					cmd = eidc32proxy.SetWebUserResponseCmd
				default:
					onErrFn(fmt.Errorf("unsupported message type '%s' (ID: %d)",
						msgType.String(), msgType))
					continue
				}

				rawResp, err := eidc32proxy.EIDCHTTPResponseBytes(&eidc32proxy.EIDCHTTPResponseData{
					StatusCode: http.StatusOK,
					WrapperBody: &eidc32proxy.EIDCSimpleResponse{
						Cmd:    cmd,
						Result: true,
					},
				})
				if err != nil {
					onErrFn(fmt.Errorf("failed to generate response for '%s' - %w",
						msgType.String(), err))
					continue
				}

				err = sendResponseFn(rawResp, msgType)
				if err != nil {
					onErrFn(fmt.Errorf("failed to send response to '%s' - %w",
						msgType.String(), err))
					continue
				}
			}
		}(c)
	}

	return errs
}
