package obfs

import (
	"bytes"
	"testing"
)

func TestXPlusObfuscator(t *testing.T) {
	x := NewXPlusObfuscator([]byte("Vaundy"))
	tests := []struct {
		name string
		p    []byte
	}{
		{name: "1", p: []byte("HelloWorld")},
		{name: "2", p: []byte("Regret is just a horrible attempt at time travel that ends with you feeling like crap")},
		{name: "3", p: []byte("To be, or not to be, that is the question:\nWhether 'tis nobler in the mind to suffer\n" +
			"The slings and arrows of outrageous fortune,\nOr to take arms against a sea of troubles\n" +
			"And by opposing end them. To die—to sleep,\nNo more; and by a sleep to say we end")},
		{name: "empty", p: []byte("")},
	}
	// Non-scat
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bb, _ := x.Obfuscate(tt.p, false)
			if len(bb) != 1 {
				t.Errorf("Incorrect number of buffers returned: %d", len(bb))
			}
			n := x.Deobfuscate(bb[0])
			if !bytes.Equal(tt.p, bb[0][:n]) {
				t.Errorf("Inconsistent deobfuscation: %s", string(bb[0][:n]))
			}
		})
	}
	// Scat
	for _, tt := range tests {
		t.Run("scat-"+tt.name, func(t *testing.T) {
			bb, _ := x.Obfuscate(tt.p, true)
			if len(bb) != 2 {
				t.Errorf("Incorrect number of buffers returned: %d", len(bb))
			}
			if len(bb[0]) != xpSaltLen || len(bb[1]) != len(tt.p) {
				t.Errorf("Incorrect buffer length: %d, %d", len(bb[0]), len(bb[1]))
			}
			var data []byte
			data = append(data, bb[0]...)
			data = append(data, bb[1]...)
			n := x.Deobfuscate(data)
			if !bytes.Equal(tt.p, data[:n]) {
				t.Errorf("Inconsistent deobfuscation: %s", string(bb[0][:n]))
			}
		})
	}
}
