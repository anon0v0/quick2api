package quick

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestEventStreamAndAIDPRoundTrip(t *testing.T) {
	inner := map[string]any{
		"type":      "text_delta",
		"thread_id": "thr-1",
		"payload":   map[string]any{"delta": "Hello world"},
	}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	outerPayload, err := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(innerBytes),
	})
	if err != nil {
		t.Fatal(err)
	}

	wire1 := EncodeEventStreamMessage(map[string]string{
		":message-type": "event",
		":event-type":   "rawOutputEvent",
	}, outerPayload)

	wire2 := EncodeEventStreamMessage(map[string]string{
		":message-type":  "exception",
		":exception-type": "ThrottlingException",
		":error-message": "Rate exceeded",
	}, nil)

	combined := append(append([]byte{}, wire1...), wire2...)

	// Feed 7 bytes at a time to test fragmentation handling.
	var dec EventStreamDecoder
	var msgs []RawEventStreamMessage
	for i := 0; i < len(combined); i += 7 {
		end := i + 7
		if end > len(combined) {
			end = len(combined)
		}
		msgs = append(msgs, dec.Feed(combined[i:end])...)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 decoded messages, got %d", len(msgs))
	}

	f1 := DecodeAIDPEvent(msgs[0])
	if f1 == nil || f1.IsError {
		t.Fatalf("unexpected frame 1: %+v", f1)
	}
	var got map[string]any
	if err := json.Unmarshal(f1.RawJSON, &got); err != nil {
		t.Fatalf("unmarshal frame 1 json: %v", err)
	}
	if got["type"] != "text_delta" || got["thread_id"] != "thr-1" {
		t.Fatalf("unexpected inner json: %+v", got)
	}

	f2 := DecodeAIDPEvent(msgs[1])
	if f2 == nil || !f2.IsError || f2.ErrorCode != "ThrottlingException" || f2.ErrorMsg != "Rate exceeded" {
		t.Fatalf("unexpected error frame 2: %+v", f2)
	}
}

func TestEncodeAIDPFrame(t *testing.T) {
	raw, err := EncodeAIDPFrame(map[string]any{"type": "ping"})
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		EventType string `json:"eventType"`
		Payload   struct {
			Payload string `json:"payload"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.EventType != "rawInputEvent" {
		t.Fatalf("expected rawInputEvent, got %q", env.EventType)
	}
	dec, err := base64.StdEncoding.DecodeString(env.Payload.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != `{"type":"ping"}` {
		t.Fatalf("unexpected decoded payload: %s", dec)
	}
}
