package eidc32proxy

import (
	"net/url"
)

//updateSessionData updates the session struct based on the contents of the message
func (o *Session) updateSessionData(msg *Message) error {
	switch msg.GetType() {
	case MsgTypeConnectedResponse:
		return o.updateSessionDataWithConnectedResponse(msg)
	case MsgTypeGetoutboundRequest:
		return o.updateSessionDataApiCredentials(msg)
	case MsgTypeGetoutboundResponse:
		return o.updateSessionDataWithGetoutboundResponse(msg)
	case MsgTypeSetWebUserRequest:
		return o.updateSessionDataWithSetWebUserRequest(msg)
	case MsgTypeEnableEventsResponse:
		return o.updateSessionDataWithEnableEventsResponse(msg)
	case MsgTypePointStatusRequest:
		return o.updateSessionDataWithPointStatusRequest(msg)
	case MsgTypeHeartbeatResponse:
		return o.updateSessionDataWithHeartbeatResponse(msg)
	default:
		return nil
	}
}

func (o *Session) updateSessionDataWithConnectedResponse(msg *Message) error {
	r, err := msg.ParseConnectedResponse()
	if err != nil {
		return err
	}
	if o.serverKeys[len(o.serverKeys)-1] != r.ServerKey {
		o.serverKeys = append(o.serverKeys, r.ServerKey)

	}
	return nil
}

func (o *Session) updateSessionDataApiCredentials(msg *Message) error {
	u, err := url.Parse(msg.Request.URL.String())
	if err != nil {
		return err
	}

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return err
	}

	o.apiCreds = UsernameAndPassword{
		username: values.Get(queryParamUsername),
		password: values.Get(queryParamPassword),
	}

	return nil
}

func (o *Session) updateSessionDataWithGetoutboundResponse(msg *Message) error {
	r, err := msg.ParseGetOutboundResponse()
	if err != nil {
		return err
	}
	o.getOutboundResponse = r
	return nil
}

func (o *Session) updateSessionDataWithSetWebUserRequest(msg *Message) error {
	r, err := msg.ParseSetWebUserRequest()
	if err != nil {
		return err
	}
	o.webCreds = UsernameAndPassword{
		username: r.User,
		password: r.Password,
	}
	return nil
}

func (o *Session) updateSessionDataWithEnableEventsResponse(msg *Message) error {
	eventsEnabled, err := msg.ParseEnableEventsResponse()
	if err != nil {
		return err
	}

	o.eventsEnabled = eventsEnabled
	return nil
}

func (o *Session) updateSessionDataWithPointStatusRequest(msg *Message) error {
	ps, err := msg.ParsePointStatusRequest()
	if err != nil {
		return err
	}
	for _, p := range ps.Points {
		o.pointStatus[p.PointID] = p
	}
	return nil
}

func (o *Session) updateSessionDataWithHeartbeatResponse(msg *Message) error {
	o.heartbeats++
	return nil
}

func (o *Session) HeartBeats() uint32 {
	return o.heartbeats
}
