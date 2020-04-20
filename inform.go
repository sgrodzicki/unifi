package unifi

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/golang/snappy"
	"io"
	"net"
)

type errUnknownField string

func (err errUnknownField) Error() string {
	return fmt.Sprintf("unknown field: %s", string(err))
}

type errInvalidPadding string

func (err errInvalidPadding) Error() string {
	return fmt.Sprintf("invalid padding: %s", string(err))
}

type errFlagNotSupported string

func (err errFlagNotSupported) Error() string {
	return fmt.Sprintf("unsupported flag: %s", string(err))
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

// ReadPacket tries to decode the input into a Packet instance.
//
// The reader is read from twice: once to fetch the header (which has a
// fixed size), and another time to read the body (its length is encoded
// in the header). This means, that the reader is not necessarily
// consumed until EOF.
//
// The returned Packet is nil if there's an error. You should not access
// its payload directly, but use the Data() function, which takes care
// of decrypting and decompressing (if necessary).
func ReadPacket(r io.Reader) (*Packet, error) {
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
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, additionalData)
	if err != nil {
		panic(err.Error())
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
