// Adapted from https://git.zx2c4.com/wireguard-go/tree/conn/bind_std.go?id=bb719d3a6e2c#n28
package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

type WSMessage struct {
	buff     []byte
	endpoint WSEndpoint
	response WSResponse
}

type WSResponse struct {
	data chan []byte
	ctx  context.Context
}

type WSBind struct {
	mu            sync.RWMutex // protects following fields
	messageChan   chan WSMessage
	responseChans map[WSEndpoint]WSResponse
}

func NewWSBind(wsChan chan WSMessage) conn.Bind {
	return &WSBind{messageChan: wsChan, responseChans: make(map[WSEndpoint]WSResponse)}
}

type WSEndpoint netip.AddrPort

var (
	_ conn.Bind     = (*WSBind)(nil)
	_ conn.Endpoint = WSEndpoint{}
)

func (*WSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return asEndpoint(e), err
}

func (*WSBind) SetMark(mark uint32) error {
	return nil
}

func (WSEndpoint) ClearSrc() {}

func (e WSEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e WSEndpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not supported
}

func (e WSEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e WSEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e WSEndpoint) SrcToString() string {
	return ""
}

func (bind *WSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{bind.makeReceiveWS()}, port, nil
}

func (bind *WSBind) Close() error {
	return nil
}

func (bind *WSBind) makeReceiveWS() conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {

		msg := <-bind.messageChan

		bind.mu.Lock()
		bind.responseChans[msg.endpoint] = msg.response
		bind.mu.Unlock()

		copy(buff, msg.buff)
		return len(msg.buff), msg.endpoint, nil
	}
}

func (bind *WSBind) Send(buff []byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(WSEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	bind.mu.RLock()
	response, ok := bind.responseChans[ep]
	bind.mu.RUnlock()
	if !ok {
		return errors.New("response channel no longer exists")
	}

	select {
	case response.data <- buff:
	case <-response.ctx.Done():
		return net.ErrClosed
	}

	return nil
}

// endpointPool contains a re-usable set of mapping from netip.AddrPort to Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an Endpoint allocates,
// but Endpoints are immutable, so we can re-use them.
var endpointPool = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]conn.Endpoint)
	},
}

// asEndpoint returns an Endpoint containing ap.
func asEndpoint(ap netip.AddrPort) conn.Endpoint {
	m := endpointPool.Get().(map[netip.AddrPort]conn.Endpoint)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = conn.Endpoint(WSEndpoint(ap))
		m[ap] = e
	}
	return e
}
