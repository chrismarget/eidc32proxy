package client

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net"
	"strings"
	"time"
)

// RandomSiteKey generates a site key string in GUUID format.
func RandomSiteKey() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// RandomServerKey generates a random server key string.
func RandomServerKey() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomInternalIPv4Address generates a random IPv4 address that might appear
// in an internal network.
func RandomInternalIPv4Address() (net.IP, error) {
	randomByte := func(allowZero bool) (byte, error) {
		for {
			b := make([]byte, 1)
			_, err := rand.Read(b)
			if err != nil {
				return 0, err
			}
			if !allowZero && b[0] == 0 {
				continue
			}
			return b[0], nil
		}
	}

	lastByte, err := randomByte(false)
	if err != nil {
		return nil, err
	}

	nets := [][]byte{
		{10, 0, 1},
		{10, 0, 2},
		{172, 16, 1},
		{192, 168, 1},
	}

	randomNetsIndex := mathrand.New(mathrand.NewSource(time.Now().Unix())).Intn(len(nets))

	return net.IPv4(nets[randomNetsIndex][0], nets[randomNetsIndex][1], nets[randomNetsIndex][2], lastByte), nil
}

// MostlyRandomMAC generates a MAC address that begins with the eIDC vendor OUI
// and ends with randomly generated bytes greater than 02:0D:F2.
func MostlyRandomMAC() (*EIDCMAC, error) {
	randomByte := func(floor byte) (byte, error) {
		for {
			b := make([]byte, 1)
			_, err := rand.Read(b)
			if err != nil {
				return 0, err
			}
			if b[0] < floor {
				continue
			}
			return b[0], nil
		}
	}

	d, err := randomByte(2)
	if err != nil {
		return nil, err
	}
	e, err := randomByte(13)
	if err != nil {
		return nil, err
	}
	f, err := randomByte(242)
	if err != nil {
		return nil, err
	}

	// First three bytes are 00 14 E4 (base 10: 00 20 228).
	addr := make(net.HardwareAddr, 6)
	addr[0] = 00
	addr[1] = 20
	addr[2] = 228
	addr[3] = d
	addr[4] = e
	addr[5] = f

	return &EIDCMAC{MAC: addr}, nil
}

// EIDCMAC is a wrapper struct that makes a normal net.HardwareAddr more
// similar to a MAC used by a eIDC.
type EIDCMAC struct {
	MAC net.HardwareAddr
}

// String returns the eIDC-like string representation of the net.HardwareAddr.
func (o EIDCMAC) String() string {
	return strings.ToUpper(o.MAC.String())
}

// SerialNumberFromMACString returns a eIDC serial number using the provided
// MAC address string. The address is validated before creating the
// serial number.
func SerialNumberFromMACString(macStr string) (string, error) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return "", err
	}

	return SerialNumberFromMAC(mac), nil
}

// SerialNumberFromMACString returns a eIDC serial number using the provided
// MAC address.
func SerialNumberFromMAC(mac net.HardwareAddr) string {
	return SerialNumberWithSuffix(strings.ToUpper(hex.EncodeToString(mac[3:])))
}

// SerialNumberWithSuffix returns a eIDC serial number without performing any
// validation on the provided serial number suffix.
func SerialNumberWithSuffix(suffix string) string {
	return fmt.Sprintf("0x000000%s", suffix)
}
