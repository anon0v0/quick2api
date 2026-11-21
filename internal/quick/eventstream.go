package quick

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
)

const (
	hvBoolTrue  = 0
	hvBoolFalse = 1
	hvByte      = 2
	hvShort     = 3
	hvInt       = 4
	hvLong      = 5
	hvBytes     = 6
	hvString    = 7
	hvTimestamp = 8
	hvUUID      = 9

	maxEventStreamMessageSize = 16 * 1024 * 1024
)

// RawEventStreamMessage is one decoded AWS EventStream binary message.
type RawEventStreamMessage struct {
	Headers map[string]any
	Payload []byte
}

// DecodedAIDPFrame is the application-level JSON frame unwrapped from AIDP EventStream.
type DecodedAIDPFrame struct {
	IsError   bool
	ErrorCode string
	ErrorMsg  string
	RawJSON   []byte
}

type aidpInputEnvelope struct {
	EventType string           `json:"eventType"`
	Payload   aidpInputPayload `json:"payload"`
}

type aidpInputPayload struct {
	Payload string `json:"payload"`
}

type aidpOutputPayload struct {
	Payload string `json:"payload"`
}

// MarshalAIDPInner encodes an inner Quick JSON frame without HTML-escaping <, >, or &
// (matching JavaScript JSON.stringify and avoiding 6x bloat on XML/HTML/code tags).
func MarshalAIDPInner(inner any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(inner); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// EncodeAIDPFrame wraps an inner Quick JSON frame into the AIDP rawInputEvent binary payload.
func EncodeAIDPFrame(inner any) ([]byte, error) {
	innerBytes, err := MarshalAIDPInner(inner)
	if err != nil {
		return nil, err
	}
	env := aidpInputEnvelope{
		EventType: "rawInputEvent",
		Payload: aidpInputPayload{
			Payload: base64.StdEncoding.EncodeToString(innerBytes),
		},
	}
	return json.Marshal(env)
}

// EventStreamDecoder drains AWS EventStream binary messages from a byte buffer.
type EventStreamDecoder struct {
	buf []byte
}

// Feed appends incoming bytes and drains all complete AWS EventStream messages.
func (d *EventStreamDecoder) Feed(chunk []byte) []RawEventStreamMessage {
	if len(chunk) > 0 {
		d.buf = append(d.buf, chunk...)
	}
	var out []RawEventStreamMessage
	pos := 0
	n := len(d.buf)

	for pos+16 <= n {
		totalLen := int(binary.BigEndian.Uint32(d.buf[pos : pos+4]))
		if totalLen < 16 || totalLen > maxEventStreamMessageSize {
			pos++
			continue
		}
		if pos+totalLen > n {
			break
		}
		headersLen := int(binary.BigEndian.Uint32(d.buf[pos+4 : pos+8]))
		preludeCRC := binary.BigEndian.Uint32(d.buf[pos+8 : pos+12])
		if crc32.ChecksumIEEE(d.buf[pos:pos+8]) != preludeCRC {
			pos++
			continue
		}
		if 12+headersLen+4 > totalLen {
			pos++
			continue
		}
		msgCRC := binary.BigEndian.Uint32(d.buf[pos+totalLen-4 : pos+totalLen])
		if crc32.ChecksumIEEE(d.buf[pos:pos+totalLen-4]) != msgCRC {
			pos += totalLen
			continue
		}

		headers := parseEventStreamHeaders(d.buf[pos+12 : pos+12+headersLen])
		payload := make([]byte, totalLen-16-headersLen)
		copy(payload, d.buf[pos+12+headersLen:pos+totalLen-4])
		out = append(out, RawEventStreamMessage{
			Headers: headers,
			Payload: payload,
		})
		pos += totalLen
	}

	if pos > 0 {
		remaining := n - pos
		if remaining > 0 {
			copy(d.buf, d.buf[pos:])
			d.buf = d.buf[:remaining]
		} else {
			d.buf = d.buf[:0]
		}
	}
	return out
}

func parseEventStreamHeaders(b []byte) map[string]any {
	hdrs := make(map[string]any)
	j := 0
	n := len(b)
	for j < n {
		nl := int(b[j])
		j++
		if j+nl >= n {
			break
		}
		name := string(b[j : j+nl])
		j += nl
		if j >= n {
			break
		}
		vt := b[j]
		j++
		switch vt {
		case hvBoolTrue:
			hdrs[name] = true
		case hvBoolFalse:
			hdrs[name] = false
		case hvByte:
			if j+1 > n {
				return hdrs
			}
			hdrs[name] = b[j]
			j++
		case hvShort:
			if j+2 > n {
				return hdrs
			}
			hdrs[name] = binary.BigEndian.Uint16(b[j : j+2])
			j += 2
		case hvInt:
			if j+4 > n {
				return hdrs
			}
			hdrs[name] = binary.BigEndian.Uint32(b[j : j+4])
			j += 4
		case hvLong, hvTimestamp:
			if j+8 > n {
				return hdrs
			}
			hdrs[name] = binary.BigEndian.Uint64(b[j : j+8])
			j += 8
		case hvBytes:
			if j+2 > n {
				return hdrs
			}
			bl := int(binary.BigEndian.Uint16(b[j : j+2]))
			j += 2
			if j+bl > n {
				return hdrs
			}
			cp := make([]byte, bl)
			copy(cp, b[j:j+bl])
			hdrs[name] = cp
			j += bl
		case hvString:
			if j+2 > n {
				return hdrs
			}
			vl := int(binary.BigEndian.Uint16(b[j : j+2]))
			j += 2
			if j+vl > n {
				return hdrs
			}
			hdrs[name] = string(b[j : j+vl])
			j += vl
		case hvUUID:
			if j+16 > n {
				return hdrs
			}
			cp := make([]byte, 16)
			copy(cp, b[j:j+16])
			hdrs[name] = cp
			j += 16
		default:
			return hdrs
		}
	}
	return hdrs
}

func headerString(h map[string]any, key string) string {
	if v, ok := h[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// DecodeAIDPEvent unwraps a RawEventStreamMessage into a DecodedAIDPFrame (nil if keepalive/ignored).
func DecodeAIDPEvent(msg RawEventStreamMessage) *DecodedAIDPFrame {
	mt := headerString(msg.Headers, ":message-type")
	if mt == "error" || mt == "exception" {
		code := headerString(msg.Headers, ":error-code")
		if code == "" {
			code = headerString(msg.Headers, ":exception-type")
		}
		if code == "" {
			code = mt
		}
		emsg := headerString(msg.Headers, ":error-message")
		if emsg == "" && len(msg.Payload) > 0 {
			var m map[string]any
			if err := json.Unmarshal(msg.Payload, &m); err == nil {
				if s, ok := m["message"].(string); ok && s != "" {
					emsg = s
				} else if s, ok := m["Message"].(string); ok && s != "" {
					emsg = s
				}
			}
			if emsg == "" {
				emsg = string(msg.Payload)
			}
		}
		return &DecodedAIDPFrame{
			IsError:   true,
			ErrorCode: code,
			ErrorMsg:  emsg,
		}
	}

	if headerString(msg.Headers, ":event-type") != "rawOutputEvent" || len(msg.Payload) == 0 {
		return nil
	}
	var outer aidpOutputPayload
	if err := json.Unmarshal(msg.Payload, &outer); err != nil || outer.Payload == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(outer.Payload)
	if err != nil {
		return nil
	}
	return &DecodedAIDPFrame{
		RawJSON: decoded,
	}
}

// EncodeEventStreamMessage encodes an AWS EventStream message (primarily for unit tests).
func EncodeEventStreamMessage(headers map[string]string, payload []byte) []byte {
	var hb []byte
	for k, v := range headers {
		hb = append(hb, byte(len(k)))
		hb = append(hb, []byte(k)...)
		hb = append(hb, hvString)
		vb := []byte(v)
		hb = binary.BigEndian.AppendUint16(hb, uint16(len(vb)))
		hb = append(hb, vb...)
	}
	headersLen := len(hb)
	totalLen := 12 + headersLen + len(payload) + 4
	msg := make([]byte, totalLen)
	binary.BigEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(msg[4:8], uint32(headersLen))
	binary.BigEndian.PutUint32(msg[8:12], crc32.ChecksumIEEE(msg[0:8]))
	copy(msg[12:12+headersLen], hb)
	copy(msg[12+headersLen:totalLen-4], payload)
	binary.BigEndian.PutUint32(msg[totalLen-4:totalLen], crc32.ChecksumIEEE(msg[0:totalLen-4]))
	return msg
}

func (f *DecodedAIDPFrame) ErrorString() string {
	if f.ErrorMsg == "" {
		return fmt.Sprintf("[%s]", f.ErrorCode)
	}
	return fmt.Sprintf("[%s] %s", f.ErrorCode, f.ErrorMsg)
}
