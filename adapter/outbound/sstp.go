package outbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/randv2"
	"github.com/metacubex/tls"
)

const (
	sstpVersion                       = 0x10
	DefaultRequestPath                = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
	DefaultUserName                   = "vpn"
	DefaultPassword                   = "vpn"
	sstpDefaultMSS                    = 1400
	sstpDefaultReadTimeout            = 10
	sstpMessageConnectRequest         = 0x0001
	sstpMessageConnectAck             = 0x0002
	sstpAttributeEncapsulatedProtocol = 0x0001
	sstpPPPProtocolIPv4               = 0x0021
	sstpPPPProtocolLCP                = 0xc021
	sstpPPPProtocolPAP                = 0xc023
	sstpPPPProtocolIPCP               = 0x8021
	sstpTCPFlagFIN                    = 0x01
	sstpTCPFlagSYN                    = 0x02
	sstpTCPFlagACK                    = 0x10
	sstpTCPFlagPSH                    = 0x08
)

type SSTP struct {
	*Base
	tlsConfig   *tls.Config
	option      *SSTPOption
	dnsResolver resolver.Resolver
}

type SSTPOption struct {
	BasicOption
	Name             string   `proxy:"name"`
	Server           string   `proxy:"server"`
	Port             int      `proxy:"port"`
	UserName         string   `proxy:"username,omitempty"`
	Password         string   `proxy:"password,omitempty"`
	SNI              string   `proxy:"sni,omitempty"`
	SkipCertVerify   bool     `proxy:"skip-cert-verify,omitempty"`
	Fingerprint      string   `proxy:"fingerprint,omitempty"`
	Certificate      string   `proxy:"certificate,omitempty"`
	PrivateKey       string   `proxy:"private-key,omitempty"`
	RequestPath      string   `proxy:"request-path,omitempty"`
	RemoteDnsResolve *bool    `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`
}

type sstpPacket struct {
	IsControl bool
	Body      []byte
}

type sstpAttribute struct {
	ID   uint16
	Data []byte
}

type sstpPPPOption struct {
	Type byte
	Data []byte
}

type sstpPPPPacket struct {
	Protocol uint16
	Code     byte
	ID       byte
	Payload  []byte
	Raw      []byte
	IPv4     []byte
}

type SSTPHandshakeOptions struct {
	Host        string
	RequestPath string
	UserName    string
	Password    string
}

type sstpClient struct {
	conn    net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	localIP netip.Addr
}

type sstpTCPConn struct {
	client *sstpClient

	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16

	seq uint32
	ack uint32

	readBuf      []byte
	remoteClosed bool
	writeMu      sync.Mutex
	closeOnce    sync.Once
	closeErr     error
}

type sstpTCPSegment struct {
	flags   byte
	seq     uint32
	ack     uint32
	payload []byte
}

func NewSSTP(option SSTPOption) (*SSTP, error) {
	sni := option.Server
	if option.SNI != "" {
		sni = option.SNI
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         sni,
		},
		Fingerprint: option.Fingerprint,
		Certificate: option.Certificate,
		PrivateKey:  option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	outbound := &SSTP{
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.SSTP,
			pdName: option.ProviderName,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		tlsConfig: tlsConfig,
		option:    &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	if outbound.option.RequestPath == "" {
		outbound.option.RequestPath = DefaultRequestPath
	}
	if outbound.option.UserName == "" {
		outbound.option.UserName = DefaultUserName
	}
	if outbound.option.Password == "" {
		outbound.option.Password = DefaultPassword
	}
	remoteDNSResolve := true
	if option.RemoteDnsResolve != nil {
		remoteDNSResolve = *option.RemoteDnsResolve
	}
	if remoteDNSResolve {
		if len(option.Dns) > 0 {
			if dns.ParseNameServer == nil {
				return nil, fmt.Errorf("sstp: dns parser is not initialized")
			}
			nss, err := dns.ParseNameServer(option.Dns)
			if err != nil {
				return nil, err
			}
			for i := range nss {
				nss[i].ProxyAdapter = outbound
			}
			outbound.dnsResolver = dns.NewResolver(dns.Config{Main: nss}).Resolver
		} else {
			rs := dns.NewResolver(dns.Config{
				Main: []dns.NameServer{
					{Net: "tcp", Addr: "1.1.1.1:53", ProxyAdapter: outbound},
					{Net: "tcp", Addr: "8.8.8.8:53", ProxyAdapter: outbound},
				},
			})
			outbound.dnsResolver = rs.Resolver
		}
	}
	return outbound, nil
}

func (s *SSTP) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	defer func(conn net.Conn) {
		safeConnClose(conn, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, s), nil
}

func (s *SSTP) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	tlsConn := tls.Client(c, s.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	targetIP, err := s.resolveTargetIP(ctx, metadata)
	if err != nil {
		return nil, err
	}
	client := NewSSTPClient(tlsConn)
	if _, err := client.Establish(SSTPHandshakeOptions{
		Host:        s.option.Server,
		RequestPath: s.option.RequestPath,
		UserName:    s.option.UserName,
		Password:    s.option.Password,
	}); err != nil {
		return nil, err
	}
	stream, err := client.DialTCP(targetIP, metadata.DstPort)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return stream, nil
}

func (s *SSTP) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func (s *SSTP) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (s *SSTP) resolveTargetIP(ctx context.Context, metadata *C.Metadata) (netip.Addr, error) {
	if metadata.Resolved() {
		ip := metadata.DstIP.Unmap()
		if !ip.Is4() {
			return netip.Addr{}, fmt.Errorf("sstp only supports IPv4 target")
		}
		return ip, nil
	}
	if metadata.Host == "" {
		return netip.Addr{}, fmt.Errorf("sstp target host is empty")
	}
	r := resolver.DefaultResolver
	if s.dnsResolver != nil {
		r = s.dnsResolver
	}
	ip, err := resolver.ResolveIPv4WithResolver(ctx, metadata.Host, r)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("sstp: resolve target %s: %w", metadata.Host, err)
	}
	metadata.DstIP = ip
	return ip, nil
}

func readSSTPPacketFrom(r io.Reader) (sstpPacket, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return sstpPacket{}, err
	}
	length := int(binary.BigEndian.Uint16(header[2:]) & 0x0fff)
	if length < 4 {
		return sstpPacket{}, fmt.Errorf("sstp: invalid packet length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return sstpPacket{}, err
	}
	return sstpPacket{IsControl: header[1]&0x01 != 0, Body: body}, nil
}

func buildSSTPControl(messageType uint16, attrs []sstpAttribute) []byte {
	attrLen := 0
	for _, attr := range attrs {
		attrLen += 4 + len(attr.Data)
	}
	packet := make([]byte, 8+attrLen)
	packet[0] = sstpVersion
	packet[1] = 0x01
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet))|0x8000)
	binary.BigEndian.PutUint16(packet[4:], messageType)
	binary.BigEndian.PutUint16(packet[6:], uint16(len(attrs)))
	offset := 8
	for _, attr := range attrs {
		binary.BigEndian.PutUint16(packet[offset:], attr.ID)
		binary.BigEndian.PutUint16(packet[offset+2:], uint16(4+len(attr.Data)))
		copy(packet[offset+4:], attr.Data)
		offset += 4 + len(attr.Data)
	}
	return packet
}

func parseSSTPControl(body []byte) (uint16, []sstpAttribute, error) {
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("sstp: short control body")
	}
	messageType := binary.BigEndian.Uint16(body[:2])
	count := int(binary.BigEndian.Uint16(body[2:4]))
	attrs := make([]sstpAttribute, 0, count)
	offset := 4
	for i := 0; i < count; i++ {
		if offset+4 > len(body) {
			return 0, nil, fmt.Errorf("sstp: truncated control attribute")
		}
		id := binary.BigEndian.Uint16(body[offset : offset+2])
		length := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		if length < 4 || offset+length > len(body) {
			return 0, nil, fmt.Errorf("sstp: invalid control attribute length %d", length)
		}
		attrs = append(attrs, sstpAttribute{ID: id, Data: append([]byte(nil), body[offset+4:offset+length]...)})
		offset += length
	}
	return messageType, attrs, nil
}

func buildSSTPData(payload []byte) []byte {
	packet := make([]byte, 6+len(payload))
	packet[0] = sstpVersion
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet))|0x8000)
	packet[4] = 0xff
	packet[5] = 0x03
	copy(packet[6:], payload)
	return packet
}

func buildSSTPPPP(protocol uint16, code, id byte, options []sstpPPPOption) []byte {
	optionsLen := 0
	for _, option := range options {
		optionsLen += 2 + len(option.Data)
	}
	frame := make([]byte, 6+optionsLen)
	binary.BigEndian.PutUint16(frame[:2], protocol)
	frame[2] = code
	frame[3] = id
	binary.BigEndian.PutUint16(frame[4:6], uint16(4+optionsLen))
	offset := 6
	for _, option := range options {
		frame[offset] = option.Type
		frame[offset+1] = byte(2 + len(option.Data))
		copy(frame[offset+2:], option.Data)
		offset += 2 + len(option.Data)
	}
	return frame
}

func buildSSTPIPv4(payload []byte) []byte {
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], sstpPPPProtocolIPv4)
	copy(frame[2:], payload)
	return frame
}

func buildSSTPPAP(id byte, userName, password string) []byte {
	user := []byte(userName)
	pass := []byte(password)
	frame := make([]byte, 2+6+len(user)+len(pass))
	binary.BigEndian.PutUint16(frame[:2], sstpPPPProtocolPAP)
	frame[2] = 0x01
	frame[3] = id
	binary.BigEndian.PutUint16(frame[4:6], uint16(6+len(user)+len(pass)))
	frame[6] = byte(len(user))
	copy(frame[7:], user)
	frame[7+len(user)] = byte(len(pass))
	copy(frame[8+len(user):], pass)
	return frame
}

func parseSSTPPPP(data []byte) *sstpPPPPacket {
	offset := 0
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0x03 {
		offset = 2
	}
	if len(data)-offset < 2 {
		return nil
	}
	protocol := binary.BigEndian.Uint16(data[offset : offset+2])
	if protocol == sstpPPPProtocolIPv4 {
		return &sstpPPPPacket{Protocol: protocol, IPv4: append([]byte(nil), data[offset+2:]...)}
	}
	if len(data)-offset < 6 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(data[offset+4 : offset+6]))
	if length < 4 || offset+2+length > len(data) {
		return nil
	}
	return &sstpPPPPacket{Protocol: protocol, Code: data[offset+2], ID: data[offset+3], Payload: append([]byte(nil), data[offset+6:offset+2+length]...), Raw: append([]byte(nil), data[offset:offset+2+length]...)}
}

func parseSSTPPPPOptions(data []byte) []sstpPPPOption {
	options := make([]sstpPPPOption, 0)
	for offset := 0; offset+2 <= len(data); {
		length := int(data[offset+1])
		if length < 2 || offset+length > len(data) {
			break
		}
		options = append(options, sstpPPPOption{Type: data[offset], Data: append([]byte(nil), data[offset+2:offset+length]...)})
		offset += length
	}
	return options
}

func buildSSTPConfigureAck(raw []byte) []byte {
	ack := append([]byte(nil), raw...)
	if len(ack) >= 3 {
		ack[2] = 0x02
	}
	return ack
}

func findSSTPIPv4Option(options []sstpPPPOption) (netip.Addr, bool) {
	for _, option := range options {
		if option.Type != 0x03 || len(option.Data) != 4 {
			continue
		}
		return netip.AddrFrom4([4]byte{option.Data[0], option.Data[1], option.Data[2], option.Data[3]}), true
	}
	return netip.Addr{}, false
}

func buildSSTPIPv4Option(addr netip.Addr) []byte {
	if !addr.IsValid() || !addr.Unmap().Is4() {
		return []byte{0, 0, 0, 0}
	}
	ip4 := addr.Unmap().As4()
	return []byte{ip4[0], ip4[1], ip4[2], ip4[3]}
}

func NewSSTPClient(conn net.Conn) *sstpClient {
	return &sstpClient{conn: conn, reader: bufio.NewReader(conn)}
}

func (c *sstpClient) Close() error {
	return c.conn.Close()
}

func (c *sstpClient) Establish(option SSTPHandshakeOptions) (netip.Addr, error) {
	path := option.RequestPath
	if path == "" {
		path = DefaultRequestPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	userName := option.UserName
	if userName == "" {
		userName = DefaultUserName
	}
	password := option.Password
	if password == "" {
		password = DefaultPassword
	}

	protocolValue := make([]byte, 2)
	binary.BigEndian.PutUint16(protocolValue, 1)
	mru := make([]byte, 2)
	binary.BigEndian.PutUint16(mru, 1500)
	request := []byte(fmt.Sprintf("SSTP_DUPLEX_POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {%s}\r\n\r\n", path, option.Host, utils.NewUUIDV4().String()))
	pppID := byte(1)
	initial := bytes.Join([][]byte{request, buildSSTPControl(sstpMessageConnectRequest, []sstpAttribute{{ID: sstpAttributeEncapsulatedProtocol, Data: protocolValue}}), buildSSTPData(buildSSTPPPP(sstpPPPProtocolLCP, 0x01, pppID, []sstpPPPOption{{Type: 0x01, Data: mru}}))}, nil)
	pppID++
	if err := c.writeAll(initial); err != nil {
		return netip.Addr{}, err
	}

	statusLine, err := c.readLine()
	if err != nil {
		return netip.Addr{}, err
	}
	for {
		line, err := c.readLine()
		if err != nil {
			return netip.Addr{}, err
		}
		if line == "" {
			break
		}
	}
	if !strings.Contains(statusLine, "200") {
		return netip.Addr{}, fmt.Errorf("sstp: unexpected HTTP response %q", statusLine)
	}
	log.Debugln("[SSTP] HTTP tunnel established to %s", option.Host)

	serverAccepted := false
	lcpDone := false
	authSent := false
	var localIP netip.Addr

	for round := 0; round < 25; round++ {
		packet, err := c.readPacketWithTimeout(time.Duration(sstpDefaultReadTimeout) * time.Second)
		if err != nil {
			return netip.Addr{}, err
		}
		if packet.IsControl {
			messageType, _, err := parseSSTPControl(packet.Body)
			if err != nil {
				continue
			}
			if !serverAccepted && messageType == sstpMessageConnectAck {
				serverAccepted = true
				log.Debugln("[SSTP] connect-ack received from %s", option.Host)
			}
			continue
		}
		pppPacket := parseSSTPPPP(packet.Body)
		if pppPacket == nil {
			continue
		}
		switch pppPacket.Protocol {
		case sstpPPPProtocolLCP:
			switch pppPacket.Code {
			case 0x01:
				payloads := [][]byte{buildSSTPData(buildSSTPConfigureAck(pppPacket.Raw))}
				if lcpDone && !authSent {
					payloads = append(payloads, buildSSTPData(buildSSTPPAP(pppID, userName, password)))
					pppID++
					authSent = true
				}
				if err := c.writeAll(bytes.Join(payloads, nil)); err != nil {
					return netip.Addr{}, err
				}
			case 0x02:
				lcpDone = true
				if !authSent {
					if err := c.writeAll(buildSSTPData(buildSSTPPAP(pppID, userName, password))); err != nil {
						return netip.Addr{}, err
					}
					pppID++
					authSent = true
				}
			}
		case sstpPPPProtocolPAP:
			if pppPacket.Code == 0x02 {
				log.Debugln("[SSTP] PAP authentication succeeded for %s", option.Host)
				ipcpRequest := buildSSTPPPP(sstpPPPProtocolIPCP, 0x01, pppID, []sstpPPPOption{{Type: 0x03, Data: []byte{0, 0, 0, 0}}})
				if err := c.writeAll(buildSSTPData(ipcpRequest)); err != nil {
					return netip.Addr{}, err
				}
				pppID++
			} else if pppPacket.Code == 0x03 {
				return netip.Addr{}, fmt.Errorf("sstp: PAP authentication rejected")
			}
		case sstpPPPProtocolIPCP:
			switch pppPacket.Code {
			case 0x01:
				if err := c.writeAll(buildSSTPData(buildSSTPConfigureAck(pppPacket.Raw))); err != nil {
					return netip.Addr{}, err
				}
			case 0x02:
				if ip, ok := findSSTPIPv4Option(parseSSTPPPPOptions(pppPacket.Payload)); ok {
					localIP = ip
				}
				if !serverAccepted {
					return netip.Addr{}, fmt.Errorf("sstp: missing connect-ack")
				}
				if !localIP.IsValid() {
					return netip.Addr{}, fmt.Errorf("sstp: missing IPCP IPv4 address")
				}
				c.localIP = localIP
				log.Debugln("[SSTP] IPCP assigned local IPv4 %s", localIP.String())
				return localIP, nil
			case 0x03:
				if ip, ok := findSSTPIPv4Option(parseSSTPPPPOptions(pppPacket.Payload)); ok {
					localIP = ip
					request := buildSSTPPPP(sstpPPPProtocolIPCP, 0x01, pppID, []sstpPPPOption{{Type: 0x03, Data: buildSSTPIPv4Option(ip)}})
					if err := c.writeAll(buildSSTPData(request)); err != nil {
						return netip.Addr{}, err
					}
					pppID++
				}
			}
		}
	}

	return netip.Addr{}, fmt.Errorf("sstp: IPCP negotiation did not finish")
}

func (c *sstpClient) readPacket() (sstpPacket, error) {
	return readSSTPPacketFrom(c.reader)
}

func (c *sstpClient) readPacketWithTimeout(timeout time.Duration) (sstpPacket, error) {
	if timeout <= 0 {
		return c.readPacket()
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return sstpPacket{}, err
	}
	defer c.conn.SetReadDeadline(time.Time{})
	return c.readPacket()
}

func (c *sstpClient) writePPPFrame(payload []byte) error {
	return c.writeAll(buildSSTPData(payload))
}

func (c *sstpClient) readLine() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *sstpClient) writeAll(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for len(payload) > 0 {
		n, err := c.conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func (c *sstpClient) DialTCP(dstIP netip.Addr, dstPort uint16) (net.Conn, error) {
	localIP := c.localIP.Unmap()
	if !localIP.IsValid() || !localIP.Is4() {
		return nil, fmt.Errorf("sstp: local IPv4 address is not available")
	}
	dstIP = dstIP.Unmap()
	if !dstIP.IsValid() || !dstIP.Is4() {
		return nil, fmt.Errorf("sstp: destination IPv4 address is required")
	}

	conn := &sstpTCPConn{client: c, srcIP: localIP, dstIP: dstIP, srcPort: uint16(10000 + randv2.IntN(50000)), dstPort: dstPort, seq: randv2.Uint32()}
	if err := conn.sendSegment(sstpTCPFlagSYN, nil); err != nil {
		return nil, err
	}
	log.Debugln("[SSTP] sent SYN to %s:%d", dstIP.String(), dstPort)
	if err := c.conn.SetReadDeadline(time.Now().Add(time.Duration(sstpDefaultReadTimeout) * time.Second)); err != nil {
		return nil, err
	}
	defer c.conn.SetReadDeadline(time.Time{})
	for i := 0; i < 30; i++ {
		packet, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		if packet.IsControl {
			continue
		}
		pppPacket := parseSSTPPPP(packet.Body)
		if pppPacket == nil || pppPacket.Protocol != sstpPPPProtocolIPv4 {
			continue
		}
		segment, ok := parseSSTPTCPPacket(pppPacket.IPv4, conn.dstIP, conn.srcIP, conn.dstPort, conn.srcPort)
		if !ok || segment.flags&(sstpTCPFlagSYN|sstpTCPFlagACK) != (sstpTCPFlagSYN|sstpTCPFlagACK) {
			continue
		}
		conn.ack = segment.seq + 1
		log.Debugln("[SSTP] received SYN/ACK from %s:%d", dstIP.String(), dstPort)
		if err := conn.sendSegment(sstpTCPFlagACK, nil); err != nil {
			return nil, err
		}
		return conn, nil
	}
	return nil, fmt.Errorf("sstp: TCP handshake timed out")
}

func (c *sstpTCPConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		return c.consumeReadBuf(b)
	}
	if c.remoteClosed {
		return 0, io.EOF
	}
	for {
		packet, err := c.client.readPacket()
		if err != nil {
			return 0, err
		}
		if packet.IsControl {
			continue
		}
		pppPacket := parseSSTPPPP(packet.Body)
		if pppPacket == nil || pppPacket.Protocol != sstpPPPProtocolIPv4 {
			continue
		}
		segment, ok := parseSSTPTCPPacket(pppPacket.IPv4, c.dstIP, c.srcIP, c.dstPort, c.srcPort)
		if !ok {
			continue
		}
		if len(segment.payload) > 0 {
			c.ack = segment.seq + uint32(len(segment.payload))
			if segment.flags&sstpTCPFlagFIN != 0 {
				c.ack++
				c.remoteClosed = true
				_ = c.sendSegment(sstpTCPFlagFIN|sstpTCPFlagACK, nil)
			} else {
				_ = c.sendSegment(sstpTCPFlagACK, nil)
			}
			c.readBuf = append(c.readBuf[:0], segment.payload...)
			return c.consumeReadBuf(b)
		}
		if segment.flags&sstpTCPFlagFIN != 0 {
			c.ack = segment.seq + 1
			c.remoteClosed = true
			_ = c.sendSegment(sstpTCPFlagFIN|sstpTCPFlagACK, nil)
			return 0, io.EOF
		}
	}
}

func (c *sstpTCPConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	written := 0
	for offset := 0; offset < len(b); offset += sstpDefaultMSS {
		end := offset + sstpDefaultMSS
		if end > len(b) {
			end = len(b)
		}
		if err := c.sendSegment(sstpTCPFlagPSH|sstpTCPFlagACK, b[offset:end]); err != nil {
			return written, err
		}
		written += end - offset
	}
	return written, nil
}

func (c *sstpTCPConn) Close() error {
	c.closeOnce.Do(func() {
		if !c.remoteClosed {
			_ = c.sendSegment(sstpTCPFlagFIN|sstpTCPFlagACK, nil)
		}
		c.closeErr = c.client.Close()
	})
	return c.closeErr
}

func (c *sstpTCPConn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(c.srcIP, c.srcPort))
}

func (c *sstpTCPConn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(c.dstIP, c.dstPort))
}

func (c *sstpTCPConn) SetDeadline(t time.Time) error {
	return c.client.conn.SetDeadline(t)
}

func (c *sstpTCPConn) SetReadDeadline(t time.Time) error {
	return c.client.conn.SetReadDeadline(t)
}

func (c *sstpTCPConn) SetWriteDeadline(t time.Time) error {
	return c.client.conn.SetWriteDeadline(t)
}

func (c *sstpTCPConn) consumeReadBuf(dst []byte) (int, error) {
	if len(c.readBuf) == 0 {
		if c.remoteClosed {
			return 0, io.EOF
		}
		return 0, nil
	}
	n := copy(dst, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if n == 0 && c.remoteClosed {
		return 0, io.EOF
	}
	return n, nil
}

func (c *sstpTCPConn) sendSegment(flags byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	segment := buildSSTPIPv4TCPPacket(c.srcIP, c.dstIP, c.srcPort, c.dstPort, c.seq, c.ack, flags, payload)
	if err := c.client.writePPPFrame(buildSSTPIPv4(segment)); err != nil {
		return err
	}
	if flags&sstpTCPFlagSYN != 0 {
		c.seq++
	}
	if flags&sstpTCPFlagFIN != 0 {
		c.seq++
	}
	c.seq += uint32(len(payload))
	return nil
}

func buildSSTPIPv4TCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	src4 := srcIP.Unmap().As4()
	dst4 := dstIP.Unmap().As4()
	totalLength := 20 + 20 + len(payload)
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(totalLength))
	binary.BigEndian.PutUint16(packet[4:], uint16(randv2.IntN(1<<16)))
	binary.BigEndian.PutUint16(packet[6:], 0x4000)
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], src4[:])
	copy(packet[16:20], dst4[:])
	binary.BigEndian.PutUint16(packet[10:], sstpChecksum(packet[:20]))

	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 0x50
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[20:], payload)

	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], sstpChecksum(pseudo))
	return packet
}

func parseSSTPTCPPacket(ipPacket []byte, expectedSrcIP, expectedDstIP netip.Addr, expectedSrcPort, expectedDstPort uint16) (sstpTCPSegment, bool) {
	if len(ipPacket) < 40 || ipPacket[9] != 6 {
		return sstpTCPSegment{}, false
	}
	ihl := int(ipPacket[0]&0x0f) * 4
	if ihl < 20 || len(ipPacket) < ihl+20 {
		return sstpTCPSegment{}, false
	}
	srcIP, ok := netip.AddrFromSlice(ipPacket[12:16])
	if !ok || srcIP != expectedSrcIP.Unmap() {
		return sstpTCPSegment{}, false
	}
	dstIP, ok := netip.AddrFromSlice(ipPacket[16:20])
	if !ok || dstIP != expectedDstIP.Unmap() {
		return sstpTCPSegment{}, false
	}
	if binary.BigEndian.Uint16(ipPacket[ihl:ihl+2]) != expectedSrcPort || binary.BigEndian.Uint16(ipPacket[ihl+2:ihl+4]) != expectedDstPort {
		return sstpTCPSegment{}, false
	}
	tcpOffset := ihl + int((ipPacket[ihl+12]>>4)&0x0f)*4
	if tcpOffset < ihl+20 || tcpOffset > len(ipPacket) {
		return sstpTCPSegment{}, false
	}
	payload := append([]byte(nil), ipPacket[tcpOffset:]...)
	return sstpTCPSegment{flags: ipPacket[ihl+13], seq: binary.BigEndian.Uint32(ipPacket[ihl+4 : ihl+8]), ack: binary.BigEndian.Uint32(ipPacket[ihl+8 : ihl+12]), payload: payload}, true
}

func sstpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
