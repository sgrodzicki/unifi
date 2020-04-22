package unifi

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elastic/ecs/code/go/ecs"
	"github.com/golang/snappy"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

type Payload struct {
	InformAsNotif  bool        `json:"inform_as_notif"`
	Architecture   string      `json:"architecture"`
	Hostname       string      `json:"hostname"`
	Serial         string      `json:"serial"`
	KernelVersion  string      `json:"kernel_version"`
	BootromVersion string      `json:"bootrom_version"`
	Version        string      `json:"version"`
	IP             string      `json:"ip"`
	MAC            string      `json:"mac"`
	Uptime         int64       `json:"uptime"`
	Model          string      `json:"model"`
	Time           int64       `json:"time"`
	TimeMs         int64       `json:"time_ms"`
	SysStats       SysStats    `json:"sys_stats"`
	SystemStats    SystemStats `json:"system-stats"`
	Interfaces     []Interface `json:"if_table"`
}

type Interface struct {
	Name      string `json:"name"`
	RXErrors  int64  `json:"rx_errors"`
	RXDropped int64  `json:"rx_dropped"`
	RXPackets int64  `json:"rx_packets"`
	RXBytes   int64  `json:"rx_bytes"`
	TXErrors  int64  `json:"tx_errors"`
	TXDropped int64  `json:"tx_dropped"`
	TXPackets int64  `json:"tx_packets"`
	TXBytes   int64  `json:"tx_bytes"`
}

type SystemStats struct {
	CPU    string `json:"cpu"`
	Memory string `json:"mem"`
	Uptime string `json:"uptime"`
}

type SysStats struct {
	Loadavg1  string `json:"loadavg_1"`
	Loadavg15 string `json:"loadavg_15"`
	Loadavg5  string `json:"loadavg_5"`
	MemBuffer int64  `json:"mem_buffer"`
	MemTotal  int64  `json:"mem_total"`
	MemUsed   int64  `json:"mem_used"`
}

func toECS(payload Payload, dataset string, system System) Document {
	ts := time.Unix(payload.Time, payload.TimeMs*1000).UTC()
	host, _ := os.Hostname()

	doc := Document{
		Time: ts,
		Agent: Agent{
			Hostname: host,
			Type:     "github.com/sgrodzicki/unifi",
			Version:  Version,
		},
		ECS: ECS{
			Version: ecs.Version,
		},
		Event: Event{
			Dataset: dataset,
			Module:  "system",
		},
		Host: Host{
			Name:         payload.Hostname,
			Hostname:     payload.Hostname,
			Architecture: payload.Architecture,
			OS: OS{
				Build:    payload.BootromVersion,
				Family:   "linux", // TODO: Remove hardcoded OS family
				Kernel:   payload.KernelVersion,
				Name:     "Linux", // TODO: Remove hardcoded OS name
				Platform: "linux", // TODO: Remove hardcoded OS platform
				Version:  payload.Version,
			},
			ID:     payload.Serial,
			IP:     payload.IP,
			MAC:    payload.MAC,
			Uptime: payload.Uptime,
			Type:   payload.Model,
		},
		Service: Service{
			Type: "system",
		},
		System: system,
	}

	return doc
}

func GenerateCpuDoc(payload Payload) Document {
	cpu, _ := strconv.ParseFloat(payload.SystemStats.CPU, 64)
	cpu /= 100

	cores := int64(1) // TODO: Add support for multiple cores
	system := System{
		CPU: &CPU{
			Cores: cores,
			System: Percentage{
				Percentage: cpu,
			},
		},
	}

	return toECS(payload, "system.cpu", system)
}

func GenerateLoadDoc(payload Payload) Document {
	load1, _ := strconv.ParseFloat(payload.SysStats.Loadavg1, 64)
	load5, _ := strconv.ParseFloat(payload.SysStats.Loadavg5, 64)
	load15, _ := strconv.ParseFloat(payload.SysStats.Loadavg15, 64)

	cores := int64(1) // TODO: Add support for multiple cores
	system := System{
		Load: &Load{
			Cores: cores,
			Normalized: Intervals{
				OneMinute:     load1 / float64(cores),
				FiveMinute:    load5 / float64(cores),
				FifteenMinute: load15 / float64(cores),
			},
			Intervals: Intervals{
				OneMinute:     load1,
				FiveMinute:    load5,
				FifteenMinute: load15,
			},
		},
	}

	return toECS(payload, "system.load", system)
}

func GenerateMemoryDoc(payload Payload) Document {
	actualPct, _ := strconv.ParseFloat(payload.SystemStats.Memory, 64)
	actualPct /= 100

	system := System{
		Memory: &Memory{
			Actual: MemoryActual{
				Free: int64(float64(payload.SysStats.MemTotal) * (1 - actualPct)),
				Used: MemoryUsed{
					Bytes:      int64(float64(payload.SysStats.MemTotal) * actualPct),
					Percentage: actualPct,
				},
			},
			Free:  payload.SysStats.MemTotal - payload.SysStats.MemUsed,
			Total: payload.SysStats.MemTotal,
			Used: MemoryUsed{
				Bytes:      payload.SysStats.MemUsed,
				Percentage: float64(payload.SysStats.MemUsed) / float64(payload.SysStats.MemTotal),
			},
		},
	}

	return toECS(payload, "system.memory", system)
}

func GenerateNetworkDocs(payload Payload) []Document {
	var docs []Document

	for _, i := range payload.Interfaces {
		system := System{
			Network: &Network{
				Name: i.Name,
				In: NetworkCounters{
					Errors:  i.RXErrors,
					Dropped: i.RXDropped,
					Packets: i.RXPackets,
					Bytes:   i.RXBytes,
				},
				Out: NetworkCounters{
					Errors:  i.TXErrors,
					Dropped: i.TXDropped,
					Packets: i.TXPackets,
					Bytes:   i.TXBytes,
				},
			},
		}

		docs = append(docs, toECS(payload, "system.network", system))
	}

	return docs
}

func Decode(key string, packet *Packet) (Payload, error) {
	payload := Payload{}

	aesKey, err := hex.DecodeString(key)
	if err != nil || len(aesKey) != 16 {
		return payload, err
	}

	data, err := packet.Data(aesKey)
	if err != nil {
		return payload, err
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return payload, err
	}

	return payload, nil
}

type errInvalidPadding string

func (err errInvalidPadding) Error() string {
	return fmt.Sprintf("invalid padding: %s", string(err))
}

type errIncompletePacket string

func (err errIncompletePacket) Error() string {
	return fmt.Sprintf("insufficient data: %v", string(err))
}

var (
	errInvalidKey   = errors.New("invalid key: must be 16 bytes long")
	errInvalidMagic = errors.New("invalid packet: must begin with 'TNBU'")
)

type headerField byte

const (
	headerMagic headerField = iota
	headerPacketVersion
	headerMAC
	headerFlags
	headerIV
	headerPayloadVersion
	headerPayloadLength
)

func (f headerField) String() string {
	switch f {
	case headerMagic:
		return "Magic"
	case headerPacketVersion:
		return "PacketVersion"
	case headerMAC:
		return "MAC"
	case headerFlags:
		return "Flags"
	case headerIV:
		return "IV"
	case headerPayloadVersion:
		return "PayloadVersion"
	case headerPayloadLength:
		return "PayloadLength"
	}
	return fmt.Sprintf("%%!unknown(%02x)", byte(f))
}

type flags uint16

// Various packet flags
const (
	Encrypted        flags = 1 << iota // packet's payload is encrypted using AES-128-CBC
	ZLibCompressed                     // the packet's payload is compressed
	SnappyCompressed                   // payload is compressed with Google's snappy algorithm
	EncryptedGCM                       // packet's payload is encrypted using AES-128-GCM
)

// fieldOrder statically describes a packet's fields, their order and the
// length of each field (in bytes).
var fieldOrder = []struct {
	name   headerField
	length int
}{
	{headerMagic, 4},
	{headerPacketVersion, 4},
	{headerMAC, 6},
	{headerFlags, 2},
	{headerIV, 16},
	{headerPayloadVersion, 4},
	{headerPayloadLength, 4},
}

// headerLength is the combined length of the inform packet's clear text
// header.
const headerLength = 0 +
	4 /* headerMagic */ +
	4 /* headerPacketVersion */ +
	6 /* headerMAC */ +
	2 /* headerFlags */ +
	16 /* headerIV */ +
	4 /* headerPayloadVersion */ +
	4 /* headerPayloadLength */

// Packet represents an HTTP POST request from an UniFi device to the controller's /inform URL.
type Packet struct {
	PacketVersion  uint32           // version of the packet
	PayloadVersion uint32           // version of the payload
	MAC            net.HardwareAddr // UniFi device's MAC address
	Flags          flags            // 0x01 = Encrypted, 0x02 = ZLibCompressed, 0x04 = SnappyCompressed, 0x08 = EncryptedGCM
	IV             []byte           // Initialization Vector for encryption
	Payload        []byte           // payload (usually JSON)
	AAD            []byte           // additional authenticated data (AAD)
}

// ParsePayload tries to decode the input into a Packet instance.
//
// The reader is read from twice: once to fetch the header (which has a
// fixed size), and another time to read the body (its length is encoded
// in the header). This means, that the reader is not necessarily
// consumed until EOF.
//
// The returned Packet is nil if there's an error. You should not access
// its payload directly, but use the Data() function, which takes care
// of decrypting and decompressing (if necessary).
func ParsePayload(r io.Reader) (*Packet, error) {
	head := make([]byte, headerLength)
	n, err := r.Read(head)
	if err != nil {
		return nil, err
	}
	if n != headerLength {
		return nil, errIncompletePacket("header too short")
	}

	off := 0
	pkt := &Packet{}
	for _, f := range fieldOrder {
		curr := head[off : off+f.length]
		switch f.name {
		case headerMagic:
			if string(curr) != "TNBU" {
				return nil, errInvalidMagic
			}
		case headerPayloadLength:
			val := binary.BigEndian.Uint32(curr)
			pkt.Payload = make([]byte, val)
		default:
			pkt.update(f.name, curr)
		}
		off += f.length
	}

	pkt.AAD = head[:40]

	if len(pkt.Payload) == 0 {
		return nil, errIncompletePacket("header does not define payload length")
	}

	if _, err = io.ReadFull(r, pkt.Payload); err != nil {
		return nil, errIncompletePacket(err.Error())
	}

	return pkt, nil
}

// update applies a partial update of the field with the given name.
func (p *Packet) update(name headerField, data []byte) {
	switch name {
	case headerPacketVersion:
		p.PacketVersion = binary.BigEndian.Uint32(data)
	case headerMAC:
		p.MAC = net.HardwareAddr(data)
	case headerFlags:
		p.Flags = flags(binary.BigEndian.Uint16(data))
	case headerIV:
		p.IV = data
	case headerPayloadVersion:
		p.PayloadVersion = binary.BigEndian.Uint32(data)
	}
}

func (p *Packet) Data(key []byte) (res []byte, err error) {
	res = p.Payload

	if p.Flags&Encrypted != 0 {
		if p.Flags&EncryptedGCM != 0 {
			if res, err = decryptGCM(key, p.IV, p.Payload, p.AAD); err != nil {
				return nil, err
			}
		} else {
			if res, err = decryptCBC(key, p.IV, p.Payload); err != nil {
				return nil, err
			}
		}
	}

	if p.Flags&ZLibCompressed != 0 {
		if res, err = decodeZlib(res); err != nil {
			return nil, err
		}
	}

	if p.Flags&SnappyCompressed != 0 {
		if res, err = decodeSnappy(res); err != nil {
			return nil, err
		}
	}

	return
}

func decryptGCM(key, iv, data, additionalData []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errInvalidKey
	}

	ciphertext := make([]byte, len(data))
	copy(ciphertext, data)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func decryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errInvalidKey
	}

	ciphertext := make([]byte, len(data))
	copy(ciphertext, data)
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errInvalidPadding("data is not padded")
	}

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return pkcs7unpad(ciphertext)
}

func pkcs7unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errInvalidPadding("no data")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errInvalidPadding("data is not padded")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errInvalidPadding("structure invalid")
		}
	}
	return b[:len(b)-n], nil
}

func decodeSnappy(data []byte) ([]byte, error) {
	return snappy.Decode(nil, data)
}

func decodeZlib(data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	z, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer z.Close()

	var res bytes.Buffer
	if _, err = io.Copy(&res, z); err != nil {
		return nil, err
	}
	return res.Bytes(), nil
}
