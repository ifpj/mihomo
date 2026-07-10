package outbound

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
)

// STUN magic cookie (RFC 5389)
var stunMagicCookie = [4]byte{0x21, 0x12, 0xA4, 0x42}

// STUN/TURN message types
const (
	stunAllocateReq uint16 = 0x0003
	stunAllocateOK  uint16 = 0x0103
	stunAllocateErr uint16 = 0x0113
	stunPermReq     uint16 = 0x0008
	stunPermOK      uint16 = 0x0108
	stunConnReq     uint16 = 0x000A
	stunConnOK      uint16 = 0x010A
	stunBindReq     uint16 = 0x000B
	stunBindOK      uint16 = 0x010B
	stunSendInd     uint16 = 0x0016
	stunDataInd     uint16 = 0x0017
)

// STUN attribute types
const (
	stunAttrUsername uint16 = 0x0006
	stunAttrMsgIntg  uint16 = 0x0008
	stunAttrErrCode  uint16 = 0x0009
	stunAttrXorPeer  uint16 = 0x0012
	stunAttrData     uint16 = 0x0013
	stunAttrRealm    uint16 = 0x0014
	stunAttrNonce    uint16 = 0x0015
	stunAttrReqTran  uint16 = 0x0019
	stunAttrConnID   uint16 = 0x002A
)

type Turn struct {
	*Base
	option      *TurnOption
	user        string
	pass        string
	dnsResolver resolver.Resolver
}

type TurnOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	UserName string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (t *Turn) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), nil
}

// StreamConnContext performs the TURN handshake over an existing control connection.
// It returns a new net.Conn (the data connection) that is tunneled to the target.
func (t *Turn) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	targetIP, err := t.resolveTargetIP(ctx, metadata)
	if err != nil {
		return nil, err
	}

	return t.turnConnect(ctx, c, targetIP, metadata.DstPort)
}

// ProxyInfo implements C.ProxyAdapter
func (t *Turn) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// ListenPacketContext implements C.ProxyAdapter using TURN UDP allocation (RFC 5766).
func (t *Turn) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	c, err := t.dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	pc, err := t.turnAllocateUDP(ctx, c)
	if err != nil {
		c.Close()
		return nil, err
	}

	return NewPacketConn(pc, t), nil
}

// turnAllocateUDP performs TURN UDP allocation and returns a net.PacketConn.
func (t *Turn) turnAllocateUDP(ctx context.Context, ctrlConn net.Conn) (net.PacketConn, error) {
	transportVal := []byte{17, 0, 0, 0} // UDP = protocol number 17

	// Step 1: unauthenticated Allocate
	if _, err := ctrlConn.Write(stunBuildMsg(stunAllocateReq, stunNewTxnID(),
		stunBuildAttr(stunAttrReqTran, transportVal),
	)); err != nil {
		return nil, fmt.Errorf("turn udp: send allocate: %w", err)
	}

	msgType, attrs, err := stunReadMsg(ctrlConn)
	if err != nil {
		return nil, fmt.Errorf("turn udp: read allocate response: %w", err)
	}

	var key []byte
	var authAttrs [][]byte

	switch {
	case msgType == stunAllocateErr && t.user != "" && stunParseErrCode(attrs[stunAttrErrCode]) == 401:
		realm := string(attrs[stunAttrRealm])
		nonce := attrs[stunAttrNonce]
		h := md5.Sum([]byte(t.user + ":" + realm + ":" + t.pass))
		key = h[:]
		authAttrs = [][]byte{
			stunBuildAttr(stunAttrUsername, []byte(t.user)),
			stunBuildAttr(stunAttrRealm, []byte(realm)),
			stunBuildAttr(stunAttrNonce, nonce),
		}
		am := stunSign(stunBuildMsg(stunAllocateReq, stunNewTxnID(),
			append([][]byte{stunBuildAttr(stunAttrReqTran, transportVal)}, authAttrs...)...,
		), key)
		if _, err := ctrlConn.Write(am); err != nil {
			return nil, fmt.Errorf("turn udp: send auth allocate: %w", err)
		}
		if msgType, _, err = stunReadMsg(ctrlConn); err != nil {
			return nil, fmt.Errorf("turn udp: read auth allocate response: %w", err)
		}
		if msgType != stunAllocateOK {
			return nil, fmt.Errorf("turn udp: allocate failed (0x%04x)", msgType)
		}
	case msgType == stunAllocateOK:
		// no auth needed
	default:
		return nil, fmt.Errorf("turn udp: unexpected allocate response (0x%04x)", msgType)
	}

	pc := &turnPacketConn{
		ctrlConn:  ctrlConn,
		key:       key,
		authAttrs: authAttrs,
		recvCh:    make(chan turnUDPPacket, 64),
		closed:    make(chan struct{}),
		perms:     make(map[string]struct{}),
	}
	go pc.readLoop()
	return pc, nil
}

type turnUDPPacket struct {
	data []byte
	addr net.Addr
}

// turnPacketConn implements net.PacketConn over a TURN UDP allocation.
// It uses Send Indication (0x0016) to send and receives Data Indication (0x0017).
type turnPacketConn struct {
	ctrlConn  net.Conn
	key       []byte
	authAttrs [][]byte
	recvCh    chan turnUDPPacket
	closed    chan struct{}
	closeOnce sync.Once
	permsMu   sync.Mutex
	perms     map[string]struct{} // permitted IPs
}

func (p *turnPacketConn) readLoop() {
	for {
		msgType, attrs, err := stunReadMsg(p.ctrlConn)
		if err != nil {
			p.Close()
			return
		}
		if msgType == stunDataInd {
			peerVal := attrs[stunAttrXorPeer]
			data := attrs[stunAttrData]
			if data == nil {
				continue
			}
			var addr net.Addr
			if peerVal != nil {
				ip, port := stunParseXorPeerAddr(peerVal)
				if ip != nil {
					addr = &net.UDPAddr{IP: ip, Port: int(port)}
				}
			}
			if addr == nil {
				addr = p.ctrlConn.RemoteAddr()
			}
			buf := make([]byte, len(data))
			copy(buf, data)
			select {
			case p.recvCh <- turnUDPPacket{data: buf, addr: addr}:
			case <-p.closed:
				return
			}
		}
	}
}

func (p *turnPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("turn udp: unsupported addr type")
	}
	tid := stunNewTxnID()
	peerVal := stunXorPeerAddr(udpAddr.IP, uint16(udpAddr.Port), tid)
	if peerVal == nil {
		return 0, fmt.Errorf("turn udp: unsupported peer address")
	}

	// Ensure CreatePermission for this IP (fire-and-forget, like JS ensurePerm)
	ipKey := udpAddr.IP.String()
	p.permsMu.Lock()
	_, hasPerm := p.perms[ipKey]
	if !hasPerm {
		p.perms[ipKey] = struct{}{}
	}
	p.permsMu.Unlock()
	if !hasPerm {
		permTid := stunNewTxnID()
		permPeer := stunXorPeerAddr(udpAddr.IP, 0, permTid)
		permAttrs := append([][]byte{stunBuildAttr(stunAttrXorPeer, permPeer)}, p.authAttrs...)
		permMsg := stunSign(stunBuildMsg(stunPermReq, permTid, permAttrs...), p.key)
		if _, err := p.ctrlConn.Write(permMsg); err != nil {
			return 0, fmt.Errorf("turn udp: send permission: %w", err)
		}
	}

	attrs := [][]byte{
		stunBuildAttr(stunAttrXorPeer, peerVal),
		stunBuildAttr(stunAttrData, b),
	}
	msg := stunBuildMsg(stunSendInd, tid, attrs...) // Send Indication: no MESSAGE-INTEGRITY per RFC 5766
	if _, err := p.ctrlConn.Write(msg); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *turnPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case pkt := <-p.recvCh:
		n := copy(b, pkt.data)
		return n, pkt.addr, nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	}
}

func (p *turnPacketConn) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.ctrlConn.Close()
	})
	return nil
}

func (p *turnPacketConn) LocalAddr() net.Addr                { return p.ctrlConn.LocalAddr() }
func (p *turnPacketConn) SetDeadline(t time.Time) error      { return p.ctrlConn.SetDeadline(t) }
func (p *turnPacketConn) SetReadDeadline(t time.Time) error  { return p.ctrlConn.SetReadDeadline(t) }
func (p *turnPacketConn) SetWriteDeadline(t time.Time) error { return p.ctrlConn.SetWriteDeadline(t) }

func NewTurn(option TurnOption) (*Turn, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	outbound := &Turn{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Turn,
			udp:    true,
			pdName: option.ProviderName,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option: &option,
		user:   option.UserName,
		pass:   option.Password,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	// Create a dedicated DNS resolver that routes queries through this TURN
	// instance's own UDP relay, so target domains are resolved from the TURN
	// server's network (trusted, unpolluted).
	rs := dns.NewResolver(dns.Config{
		Main: []dns.NameServer{
			{Addr: "1.1.1.1:53", ProxyAdapter: outbound},
			{Addr: "8.8.8.8:53", ProxyAdapter: outbound},
		},
	})
	outbound.dnsResolver = rs.Resolver

	return outbound, nil
}

// resolveTargetIP resolves the target address from metadata to a net.IP.
// When the target is not yet resolved, it uses the TURN instance's own DNS
// resolver which routes queries through the TURN UDP relay to 8.8.8.8,
// avoiding local DNS pollution.
func (t *Turn) resolveTargetIP(ctx context.Context, metadata *C.Metadata) (net.IP, error) {
	if metadata.Resolved() {
		return metadata.DstIP.AsSlice(), nil
	}
	ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, t.dnsResolver)
	if err != nil {
		return nil, fmt.Errorf("turn: resolve target %s: %w", metadata.Host, err)
	}
	return ip.AsSlice(), nil
}

// turnConnect performs the full TURN TCP Connect handshake (RFC 6062).
//
// Protocol flow:
//  1. Allocate Request → 401 Error (get realm/nonce)
//  2. Authenticated Allocate + CreatePermission + Connect (pipelined)
//  3. Read Allocate OK, Permission OK, Connect OK (get CONNECTION-ID)
//  4. Open data connection → ConnectionBind with CONNECTION-ID
//  5. Data connection becomes a transparent TCP tunnel
func (t *Turn) turnConnect(ctx context.Context, ctrlConn net.Conn, targetIP net.IP, targetPort uint16) (net.Conn, error) {
	transportVal := []byte{6, 0, 0, 0} // TCP = protocol number 6

	// Step 1: Send unauthenticated Allocate Request
	if _, err := ctrlConn.Write(stunBuildMsg(stunAllocateReq, stunNewTxnID(),
		stunBuildAttr(stunAttrReqTran, transportVal),
	)); err != nil {
		return nil, fmt.Errorf("turn: send allocate: %w", err)
	}

	msgType, attrs, err := stunReadMsg(ctrlConn)
	if err != nil {
		return nil, fmt.Errorf("turn: read allocate response: %w", err)
	}

	var key []byte
	var authAttrs [][]byte

	switch {
	case msgType == stunAllocateErr && t.user != "" && stunParseErrCode(attrs[stunAttrErrCode]) == 401:
		// 401 Unauthorized - compute long-term credential key: MD5(user:realm:pass)
		realm := string(attrs[stunAttrRealm])
		nonce := attrs[stunAttrNonce]
		h := md5.Sum([]byte(t.user + ":" + realm + ":" + t.pass))
		key = h[:]

		authAttrs = [][]byte{
			stunBuildAttr(stunAttrUsername, []byte(t.user)),
			stunBuildAttr(stunAttrRealm, []byte(realm)),
			stunBuildAttr(stunAttrNonce, nonce),
		}

		// Pipeline: authenticated Allocate + CreatePermission + Connect
		am := stunSign(stunBuildMsg(stunAllocateReq, stunNewTxnID(),
			append([][]byte{stunBuildAttr(stunAttrReqTran, transportVal)}, authAttrs...)...,
		), key)
		pm := t.buildPeerMsg(stunPermReq, targetIP, targetPort, key, authAttrs)
		cm := t.buildPeerMsg(stunConnReq, targetIP, targetPort, key, authAttrs)
		if pm == nil || cm == nil {
			return nil, fmt.Errorf("turn: unsupported target address format")
		}

		buf := make([]byte, 0, len(am)+len(pm)+len(cm))
		buf = append(buf, am...)
		buf = append(buf, pm...)
		buf = append(buf, cm...)
		if _, err := ctrlConn.Write(buf); err != nil {
			return nil, fmt.Errorf("turn: send auth requests: %w", err)
		}

		// Read Allocate OK
		if msgType, _, err = stunReadMsg(ctrlConn); err != nil {
			return nil, fmt.Errorf("turn: read allocate ok: %w", err)
		}
		if msgType != stunAllocateOK {
			return nil, fmt.Errorf("turn: allocate failed (0x%04x)", msgType)
		}

	case msgType == stunAllocateOK:
		// No auth required - pipeline: CreatePermission + Connect
		pm := t.buildPeerMsg(stunPermReq, targetIP, targetPort, nil, nil)
		cm := t.buildPeerMsg(stunConnReq, targetIP, targetPort, nil, nil)
		if pm == nil || cm == nil {
			return nil, fmt.Errorf("turn: unsupported target address format")
		}

		buf := make([]byte, 0, len(pm)+len(cm))
		buf = append(buf, pm...)
		buf = append(buf, cm...)
		if _, err := ctrlConn.Write(buf); err != nil {
			return nil, fmt.Errorf("turn: send perm+connect: %w", err)
		}

	default:
		return nil, fmt.Errorf("turn: unexpected allocate response (0x%04x)", msgType)
	}

	// Read CreatePermission OK
	if msgType, _, err = stunReadMsg(ctrlConn); err != nil {
		return nil, fmt.Errorf("turn: read permission response: %w", err)
	}
	if msgType != stunPermOK {
		return nil, fmt.Errorf("turn: create permission failed (0x%04x)", msgType)
	}

	// Read Connect OK - contains CONNECTION-ID
	msgType, attrs, err = stunReadMsg(ctrlConn)
	if err != nil {
		return nil, fmt.Errorf("turn: read connect response: %w", err)
	}
	if msgType != stunConnOK {
		return nil, fmt.Errorf("turn: connect failed (0x%04x)", msgType)
	}
	connID := attrs[stunAttrConnID]
	if connID == nil {
		return nil, fmt.Errorf("turn: missing CONNECTION-ID in connect response")
	}

	// Step 2: Open data connection and perform ConnectionBind
	dataConn, err := t.dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("turn: dial data connection: %w", err)
	}

	// Set deadline for the bind handshake
	if deadline, ok := ctx.Deadline(); ok {
		dataConn.SetDeadline(deadline)
	}

	bindAttrs := append([][]byte{stunBuildAttr(stunAttrConnID, connID)}, authAttrs...)
	bindMsg := stunSign(stunBuildMsg(stunBindReq, stunNewTxnID(), bindAttrs...), key)
	if _, err := dataConn.Write(bindMsg); err != nil {
		dataConn.Close()
		return nil, fmt.Errorf("turn: send connection bind: %w", err)
	}

	msgType, _, err = stunReadMsg(dataConn)
	if err != nil {
		dataConn.Close()
		return nil, fmt.Errorf("turn: read bind response: %w", err)
	}
	if msgType != stunBindOK {
		dataConn.Close()
		return nil, fmt.Errorf("turn: connection bind failed (0x%04x)", msgType)
	}

	// Clear deadline - data connection is now a transparent TCP tunnel
	dataConn.SetDeadline(time.Time{})

	return &turnDataConn{Conn: dataConn, ctrlConn: ctrlConn}, nil
}

// buildPeerMsg builds a STUN message containing XOR-PEER-ADDRESS for the target.
func (t *Turn) buildPeerMsg(msgType uint16, targetIP net.IP, targetPort uint16, key []byte, authAttrs [][]byte) []byte {
	tid := stunNewTxnID()
	peerVal := stunXorPeerAddr(targetIP, targetPort, tid)
	if peerVal == nil {
		return nil
	}
	attrs := append([][]byte{stunBuildAttr(stunAttrXorPeer, peerVal)}, authAttrs...)
	return stunSign(stunBuildMsg(msgType, tid, attrs...), key)
}

// turnDataConn wraps the TURN data connection and ensures the control connection is closed together.
type turnDataConn struct {
	net.Conn
	ctrlConn net.Conn
}

func (c *turnDataConn) Close() error {
	c.ctrlConn.Close()
	return c.Conn.Close()
}

// --- STUN protocol helpers ---

func stunBuildAttr(attrType uint16, value []byte) []byte {
	padLen := (4 - len(value)%4) % 4
	b := make([]byte, 4+len(value)+padLen)
	binary.BigEndian.PutUint16(b, attrType)
	binary.BigEndian.PutUint16(b[2:], uint16(len(value)))
	copy(b[4:], value)
	return b
}

func stunBuildMsg(msgType uint16, tid [12]byte, attrs ...[]byte) []byte {
	bodyLen := 0
	for _, a := range attrs {
		bodyLen += len(a)
	}
	msg := make([]byte, 20+bodyLen)
	binary.BigEndian.PutUint16(msg, msgType)
	binary.BigEndian.PutUint16(msg[2:], uint16(bodyLen))
	copy(msg[4:8], stunMagicCookie[:])
	copy(msg[8:20], tid[:])
	off := 20
	for _, a := range attrs {
		copy(msg[off:], a)
		off += len(a)
	}
	return msg
}

func stunNewTxnID() [12]byte {
	var tid [12]byte
	_, _ = rand.Read(tid[:])
	return tid
}

// stunXorPeerAddr encodes an XOR-PEER-ADDRESS attribute value (RFC 5389 Section 15.2).
// For IPv4: XOR with magic cookie. For IPv6: XOR with magic cookie + transaction ID.
func stunXorPeerAddr(ip net.IP, port uint16, tid [12]byte) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		b := make([]byte, 8)
		b[1] = 0x01 // IPv4 family
		binary.BigEndian.PutUint16(b[2:], port^0x2112)
		for i := 0; i < 4; i++ {
			b[4+i] = ip4[i] ^ stunMagicCookie[i]
		}
		return b
	}
	if ip6 := ip.To16(); ip6 != nil {
		b := make([]byte, 20)
		b[1] = 0x02 // IPv6 family
		binary.BigEndian.PutUint16(b[2:], port^0x2112)
		var xorKey [16]byte
		copy(xorKey[:4], stunMagicCookie[:])
		copy(xorKey[4:], tid[:])
		for i := 0; i < 16; i++ {
			b[4+i] = ip6[i] ^ xorKey[i]
		}
		return b
	}
	return nil
}

// stunParseXorPeerAddr decodes an XOR-PEER-ADDRESS attribute value back to IP and port.
func stunParseXorPeerAddr(b []byte) (net.IP, uint16) {
	if len(b) < 8 {
		return nil, 0
	}
	port := binary.BigEndian.Uint16(b[2:]) ^ 0x2112
	if b[1] == 0x01 && len(b) >= 8 {
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = b[4+i] ^ stunMagicCookie[i]
		}
		return ip, port
	}
	if b[1] == 0x02 && len(b) >= 20 {
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			ip[i] = b[4+i] ^ stunMagicCookie[i%4]
		}
		return ip, port
	}
	return nil, 0
}

// stunSign adds MESSAGE-INTEGRITY to a STUN message using HMAC-SHA1.
func stunSign(msg []byte, key []byte) []byte {
	if key == nil {
		return msg
	}
	// Adjust the length field to include MESSAGE-INTEGRITY attribute (4 + 20 = 24 bytes)
	adjusted := make([]byte, len(msg))
	copy(adjusted, msg)
	binary.BigEndian.PutUint16(adjusted[2:], uint16(len(msg)-20+24))

	mac := hmac.New(sha1.New, key)
	mac.Write(adjusted)
	return append(adjusted, stunBuildAttr(stunAttrMsgIntg, mac.Sum(nil))...)
}

// stunReadMsg reads and parses one STUN message from a reader.
func stunReadMsg(r io.Reader) (msgType uint16, attrs map[uint16][]byte, err error) {
	hdr := make([]byte, 20)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	if hdr[4] != stunMagicCookie[0] || hdr[5] != stunMagicCookie[1] ||
		hdr[6] != stunMagicCookie[2] || hdr[7] != stunMagicCookie[3] {
		return 0, nil, fmt.Errorf("invalid STUN magic cookie")
	}

	msgType = binary.BigEndian.Uint16(hdr)
	bodyLen := int(binary.BigEndian.Uint16(hdr[2:]))
	attrs = make(map[uint16][]byte)

	if bodyLen > 0 {
		body := make([]byte, bodyLen)
		if _, err = io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
		for o := 0; o+4 <= bodyLen; {
			at := binary.BigEndian.Uint16(body[o:])
			al := int(binary.BigEndian.Uint16(body[o+2:]))
			if o+4+al > bodyLen {
				break
			}
			v := make([]byte, al)
			copy(v, body[o+4:])
			attrs[at] = v
			o += 4 + al + (4-al%4)%4
		}
	}
	return
}

// stunParseErrCode extracts the error code from an ERROR-CODE attribute value.
func stunParseErrCode(d []byte) int {
	if len(d) < 4 {
		return 0
	}
	return int(d[2]&7)*100 + int(d[3])
}
