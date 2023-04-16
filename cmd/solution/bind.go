// Adapted from https://git.zx2c4.com/wireguard-go/tree/conn/bind_std.go?id=bb719d3a6e2c#n28
package main

import (
	"context"
	"fmt"
	"kraken/util"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"nhooyr.io/websocket"
)

type WSBind struct {
	mu             sync.Mutex // protects following fields
	wsConn         net.Conn
	connCreated    chan bool
	ctx            context.Context
	cancel         context.CancelFunc
	endpoint       conn.Endpoint
	pubKey         string
	clientAddr     netip.Addr
	serverAddrPort string
}

func NewWSBind(pubKey string, clientAddr netip.Addr, serverAddrPort string) conn.Bind {
	return &WSBind{connCreated: make(chan bool, 1), pubKey: pubKey, clientAddr: clientAddr, serverAddrPort: serverAddrPort}
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
	bind.mu.Lock()
	defer bind.mu.Unlock()

	bind.ctx, bind.cancel = context.WithTimeout(context.Background(), time.Minute)
	return []conn.ReceiveFunc{bind.makeReceiveWS()}, port, nil
}

func (bind *WSBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.wsConn != nil {
		err := bind.wsConn.Close()
		if err != nil {
			return err
		}
		bind.wsConn = nil
		bind.cancel()
	}

	return nil
}

func (bind *WSBind) makeReceiveWS() conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		if bind.wsConn == nil {
			select {
			case <-bind.connCreated:
			case <-bind.ctx.Done():
				return 0, WSEndpoint{}, net.ErrClosed
			}
		}

		n, err := bind.wsConn.Read(buff)
		return n, bind.endpoint, err
	}
}

func (bind *WSBind) Send(buff []byte, endpoint conn.Endpoint) error {
	var err error

	if bind.wsConn == nil {
		bind.mu.Lock()
		c, _, err := websocket.Dial(bind.ctx, fmt.Sprintf("ws://%s/ws?pub=%s&addr=%s", bind.serverAddrPort, util.Base64KeyToUrl(bind.pubKey), bind.clientAddr.String()), nil)
		//c, _, err := websocket.Dial(bind.ctx, fmt.Sprintf("ws://%s/ws?pub=%s&addr=%s", bind.serverAddrPort, "YXNkZg", bind.clientAddr.String()), nil)

		if err != nil {
			bind.wsConn = nil
			return err
		}

		bind.wsConn = websocket.NetConn(bind.ctx, c, websocket.MessageBinary)

		bind.endpoint = endpoint
		bind.connCreated <- true
		bind.mu.Unlock()
	}

	_, err = bind.wsConn.Write(buff)
	return err
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
