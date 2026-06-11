package msf

import (
	"encoding/binary"
	"fmt"
	"math"
)

// This is a focused MessagePack codec covering exactly the subset the
// Metasploit RPC API uses: nil, bool, ints, floats, strings/binary, arrays, and
// maps. Metasploit encodes most strings as MessagePack `bin`, and map keys come
// back as bin/str — both decode to Go strings here.

// mpEncode serializes a value to MessagePack. Supported Go types: nil, bool,
// int/int64, float64, string, []interface{}, map[string]interface{}.
func mpEncode(v interface{}) []byte {
	var b []byte
	return encodeValue(b, v)
}

func encodeValue(b []byte, v interface{}) []byte {
	switch x := v.(type) {
	case nil:
		return append(b, 0xc0)
	case bool:
		if x {
			return append(b, 0xc3)
		}
		return append(b, 0xc2)
	case int:
		return encodeInt(b, int64(x))
	case int64:
		return encodeInt(b, x)
	case float64:
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], math.Float64bits(x))
		return append(append(b, 0xcb), tmp[:]...)
	case string:
		return encodeString(b, x)
	case []byte:
		return encodeString(b, string(x))
	case []interface{}:
		b = encodeArrayHeader(b, len(x))
		for _, e := range x {
			b = encodeValue(b, e)
		}
		return b
	case map[string]interface{}:
		b = encodeMapHeader(b, len(x))
		for k, val := range x {
			b = encodeString(b, k)
			b = encodeValue(b, val)
		}
		return b
	default:
		// Unknown types encode as nil rather than panic.
		return append(b, 0xc0)
	}
}

func encodeInt(b []byte, n int64) []byte {
	switch {
	case n >= 0 && n < 128:
		return append(b, byte(n))
	case n < 0 && n >= -32:
		return append(b, byte(n))
	default:
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], uint64(n))
		return append(append(b, 0xd3), tmp[:]...)
	}
}

func encodeString(b []byte, s string) []byte {
	n := len(s)
	switch {
	case n < 32:
		b = append(b, 0xa0|byte(n))
	case n < 256:
		b = append(b, 0xd9, byte(n))
	case n < 65536:
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], uint16(n))
		b = append(append(b, 0xda), tmp[:]...)
	default:
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], uint32(n))
		b = append(append(b, 0xdb), tmp[:]...)
	}
	return append(b, s...)
}

func encodeArrayHeader(b []byte, n int) []byte {
	switch {
	case n < 16:
		return append(b, 0x90|byte(n))
	case n < 65536:
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], uint16(n))
		return append(append(b, 0xdc), tmp[:]...)
	default:
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], uint32(n))
		return append(append(b, 0xdd), tmp[:]...)
	}
}

func encodeMapHeader(b []byte, n int) []byte {
	switch {
	case n < 16:
		return append(b, 0x80|byte(n))
	case n < 65536:
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], uint16(n))
		return append(append(b, 0xde), tmp[:]...)
	default:
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], uint32(n))
		return append(append(b, 0xdf), tmp[:]...)
	}
}

// mpDecode parses a single MessagePack value. bin/str both become string; maps
// become map[string]interface{}; arrays become []interface{}; ints become int64.
func mpDecode(data []byte) (interface{}, error) {
	d := &decoder{data: data}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	return v, nil
}

type decoder struct {
	data []byte
	pos  int
}

func (d *decoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, fmt.Errorf("msgpack: unexpected end of data")
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) readN(n int) ([]byte, error) {
	if d.pos+n > len(d.data) {
		return nil, fmt.Errorf("msgpack: unexpected end of data")
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

func (d *decoder) value() (interface{}, error) {
	c, err := d.readByte()
	if err != nil {
		return nil, err
	}

	switch {
	case c <= 0x7f: // positive fixint
		return int64(c), nil
	case c >= 0xe0: // negative fixint
		return int64(int8(c)), nil
	case c >= 0x80 && c <= 0x8f: // fixmap
		return d.readMap(int(c & 0x0f))
	case c >= 0x90 && c <= 0x9f: // fixarray
		return d.readArray(int(c & 0x0f))
	case c >= 0xa0 && c <= 0xbf: // fixstr
		return d.readStr(int(c & 0x1f))
	}

	switch c {
	case 0xc0:
		return nil, nil
	case 0xc2:
		return false, nil
	case 0xc3:
		return true, nil
	case 0xc4: // bin8
		return d.readBin(1)
	case 0xc5: // bin16
		return d.readBin(2)
	case 0xc6: // bin32
		return d.readBin(4)
	case 0xca: // float32
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), nil
	case 0xcb: // float64
		b, err := d.readN(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
	case 0xcc:
		return d.readUint(1)
	case 0xcd:
		return d.readUint(2)
	case 0xce:
		return d.readUint(4)
	case 0xcf:
		return d.readUint(8)
	case 0xd0:
		return d.readSint(1)
	case 0xd1:
		return d.readSint(2)
	case 0xd2:
		return d.readSint(4)
	case 0xd3:
		return d.readSint(8)
	case 0xd9: // str8
		return d.readStrN(1)
	case 0xda: // str16
		return d.readStrN(2)
	case 0xdb: // str32
		return d.readStrN(4)
	case 0xdc: // array16
		n, err := d.readLen(2)
		if err != nil {
			return nil, err
		}
		return d.readArray(n)
	case 0xdd: // array32
		n, err := d.readLen(4)
		if err != nil {
			return nil, err
		}
		return d.readArray(n)
	case 0xde: // map16
		n, err := d.readLen(2)
		if err != nil {
			return nil, err
		}
		return d.readMap(n)
	case 0xdf: // map32
		n, err := d.readLen(4)
		if err != nil {
			return nil, err
		}
		return d.readMap(n)
	}
	return nil, fmt.Errorf("msgpack: unsupported byte 0x%02x", c)
}

func (d *decoder) readStr(n int) (string, error) {
	b, err := d.readN(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (d *decoder) readStrN(lenBytes int) (string, error) {
	n, err := d.readLen(lenBytes)
	if err != nil {
		return "", err
	}
	return d.readStr(n)
}

func (d *decoder) readBin(lenBytes int) (string, error) {
	n, err := d.readLen(lenBytes)
	if err != nil {
		return "", err
	}
	return d.readStr(n)
}

func (d *decoder) readLen(lenBytes int) (int, error) {
	b, err := d.readN(lenBytes)
	if err != nil {
		return 0, err
	}
	switch lenBytes {
	case 1:
		return int(b[0]), nil
	case 2:
		return int(binary.BigEndian.Uint16(b)), nil
	default:
		return int(binary.BigEndian.Uint32(b)), nil
	}
}

func (d *decoder) readUint(n int) (interface{}, error) {
	b, err := d.readN(n)
	if err != nil {
		return nil, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return int64(v), nil
}

func (d *decoder) readSint(n int) (interface{}, error) {
	b, err := d.readN(n)
	if err != nil {
		return nil, err
	}
	var v int64
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v, nil
}

func (d *decoder) readArray(n int) (interface{}, error) {
	out := make([]interface{}, n)
	for i := 0; i < n; i++ {
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func (d *decoder) readMap(n int) (interface{}, error) {
	out := make(map[string]interface{}, n)
	for i := 0; i < n; i++ {
		k, err := d.value()
		if err != nil {
			return nil, err
		}
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		out[fmt.Sprint(k)] = v
	}
	return out, nil
}
