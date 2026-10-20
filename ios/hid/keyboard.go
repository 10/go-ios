package hid

import (
	"fmt"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/xpc"
)

const (
	// KeyStep is how long each key report waits after the one before.
	KeyStep = 60 * time.Millisecond
	// KeyboardSettle is how long an attached keyboard waits before its first
	// report: the device drops keys until it routes the new keyboard.
	KeyboardSettle = 300 * time.Millisecond

	keyboardWithin = 5 * time.Second

	reportIDKeyboard  = 0x01
	keyboardReportLen = 39
	maxKeyboardUsage  = 239
)

// keyboardID is the service id this end chooses for its keyboard; the high half
// marks it as a peripheral lent to the device, as a Mac's are over Universal Control.
const keyboardID uint64 = 0x100002001

// keyboardDescriptor declares a boot-protocol keyboard (Generic Desktop page,
// usage Keyboard). The device reads its reports as a bitmap of the usages held
// down whatever this says of their layout; the descriptor only makes it a keyboard.
var keyboardDescriptor = []byte{
	0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, // Generic Desktop, Keyboard, Collection (Application)
	0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x95, 0x08, 0x75, 0x01, 0x81, 0x02, // modifier bits
	0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // reserved byte
	0x05, 0x07, 0x19, 0x00, 0x29, 0xFF, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x95, 0x06, 0x75, 0x08, 0x81, 0x00, // six keys
	0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x15, 0x00, 0x25, 0x01, 0x95, 0x05, 0x75, 0x01, 0x91, 0x02, // LEDs
	0x95, 0x01, 0x75, 0x03, 0x91, 0x01, // LED padding
	0xC0,
}

// Keyboard is a virtual keyboard attached to one device. While it is attached
// the device hides its on-screen keyboard. A media stream has to be running, or
// the device drops the keys.
type Keyboard struct {
	mutex sync.Mutex
	conn  *xpc.Connection
	id    uint64
}

// AttachKeyboard lends the device a keyboard on a connection of its own, then
// waits KeyboardSettle. The device drops the keyboard, with any key still down,
// when that connection closes.
func AttachKeyboard(device ios.DeviceEntry) (*Keyboard, error) {
	conn, err := ios.ConnectToXpcServiceTunnelIface(device, universalServiceName)
	if err != nil {
		return nil, fmt.Errorf("AttachKeyboard: %w", err)
	}
	id, err := registerKeyboard(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("AttachKeyboard: %w", err)
	}
	time.Sleep(KeyboardSettle)
	return &Keyboard{conn: conn, id: id}, nil
}

// Detach waits for the last report to land, then takes the keyboard back.
func (k *Keyboard) Detach() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	time.Sleep(KeyStep)
	return k.conn.Close()
}

// Press presses each chord of HID keyboard usages (page 0x07) in turn. A
// chord's keys go down in order and come up in reverse, one report each, so
// {Shift, A} is Shift down, A down, A up, Shift up.
func (k *Keyboard) Press(chords ...[]uint8) error {
	for _, chord := range chords {
		for _, usage := range chord {
			if usage > maxKeyboardUsage {
				return fmt.Errorf("Press: a key report has no room for usage %d", usage)
			}
		}
	}
	k.mutex.Lock()
	defer k.mutex.Unlock()
	for _, chord := range chords {
		for i := range chord {
			if err := k.send(chord[:i+1]); err != nil {
				return err
			}
		}
		for i := len(chord) - 1; i >= 0; i-- {
			if err := k.send(chord[:i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Type types text with a US layout. A shifted character sends Shift in its own
// report before the key. "\n" is Return, "\t" Tab and "\b" Backspace.
func (k *Keyboard) Type(text string) error {
	chords := make([][]uint8, 0, len(text))
	for _, r := range text {
		chord, ok := usLayout[r]
		if !ok {
			return fmt.Errorf("Type: %q is not on a US keyboard", r)
		}
		chords = append(chords, chord)
	}
	return k.Press(chords...)
}

func (k *Keyboard) send(held []uint8) error {
	if err := k.conn.Send(buildSendReportPayload(k.id, buildKeyboardReport(held, timestamp())), xpc.HeartbeatRequestFlag); err != nil {
		return fmt.Errorf("failed to send a key report: %w", err)
	}
	time.Sleep(KeyStep)
	return nil
}

func registerKeyboard(conn *xpc.Connection) (uint64, error) {
	if err := conn.Send(buildCreateKeyboardPayload(), xpc.HeartbeatRequestFlag); err != nil {
		return 0, fmt.Errorf("failed to send the keyboard: %w", err)
	}
	timer := time.AfterFunc(keyboardWithin, func() { _ = conn.Close() })
	defer timer.Stop()
	reply, err := conn.ReceiveOnServerClientStream()
	if err != nil {
		return 0, fmt.Errorf("the device did not take the keyboard: %w", err)
	}
	switch id := reply["serviceID"].(type) {
	case uint64:
		return id, nil
	case int64:
		return uint64(id), nil
	}
	return 0, fmt.Errorf("the device answered the keyboard with %v", reply)
}

// buildKeyboardReport is the report of the usages held down: report id 1, a
// bitmap of usages 0-239 (usage u is bit u%8 of byte 1+u/8) and a timestamp.
func buildKeyboardReport(held []uint8, ts uint64) []byte {
	report := make([]byte, keyboardReportLen)
	report[0] = reportIDKeyboard
	for _, usage := range held {
		report[1+usage/8] |= 1 << (usage % 8)
	}
	putTimestamp(report[31:37], ts)
	return report
}

const (
	usageLeftShift = 0xE1
	usageReturn    = 0x28
	usageBackspace = 0x2A
	usageTab       = 0x2B
	usageSpace     = 0x2C
)

var usLayout = buildUSLayout()

func buildUSLayout() map[rune][]uint8 {
	layout := map[rune][]uint8{
		'\n': {usageReturn},
		'\b': {usageBackspace},
		'\t': {usageTab},
		' ':  {usageSpace},
	}
	key := func(usage uint8, plain, shifted rune) {
		layout[plain] = []uint8{usage}
		layout[shifted] = []uint8{usageLeftShift, usage}
	}
	for i := range 26 {
		key(0x04+uint8(i), rune('a'+i), rune('A'+i))
	}
	for i, plain := range "1234567890" {
		key(0x1E+uint8(i), plain, rune("!@#$%^&*()"[i]))
	}
	for i, plain := range "-=[]\\" {
		key(0x2D+uint8(i), plain, rune("_+{}|"[i]))
	}
	for i, plain := range ";'`,./" {
		key(0x33+uint8(i), plain, rune(":\"~<>?"[i]))
	}
	return layout
}
