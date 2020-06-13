package nftset

import (
	"encoding/binary"
	"net"
	"testing"
)

// TODO: it's full manual now, so make these actually automated

/*
table inet filter {
        set ndmacok {
                type ether_addr
                elements = { aa:bb:cc:dd:ee:ff }
        }
}
*/
func TestSetMacAddr(t *testing.T) {
	c := &Conn{}
	s, err := c.NewSet("filter","ndmacok")
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	s.Map[string(mac)] = nil
	mac, _ = net.ParseMAC("aa:bb:cc:dd:ee:f2")
	s.Map[string(mac)] = nil
	err = s.Update()
	t.Log(err)
	delete(s.Map, string(mac))
	err = s.Update()
	t.Log(err)
}

/*
table ip nat {
        set fwok {
                type ipv4_addr
				elements = elements = { 1.2.3.4 }
		}
}
 */
func TestSetIpAddr(t *testing.T) {
	c := &Conn{}
	s, err := c.NewSet("nat","fwok")
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("1.2.3.4").To4()
	s.Map[string(ip)] = nil
	ip = net.ParseIP("1.2.3.5").To4()
	s.Map[string(ip)] = nil
	err = s.Update()
	delete(s.Map, string(ip))
	err = s.Update()
	t.Log(err)
}

/*
table ip nat {
        map dstnat {
                type ipv4_addr
				elements = elements = { 1.2.3.4 : 5.6.7.8 }
		}
}
*/
func TestMapIpAddr(t *testing.T) {
	c := &Conn{}
	s, err := c.NewSet("nat","dstnat")
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("1.2.3.4").To4()
	ip2 := net.ParseIP("5.6.7.8").To4()
	s.Map[string(ip)] = ip2
	err = s.Update()
	t.Log(err)

	ip = net.ParseIP("2.3.4.5").To4()
	ip2 = net.ParseIP("6.7.8.9").To4()
	s.Map[string(ip)] = ip2
	err = s.Update()
	t.Log(err)

	delete(s.Map, string(ip))
	err = s.Update()
	t.Log(err)
}

/*
table ip nat {
        map pmptcp_ip {
                type ipv4_addr . inet_service : ipv4_addr
        }
}
*/
func TestMapIpPortToIP(t *testing.T) {
	c := &Conn{}
	s, err := c.NewSet("nat","pmptcp_ip")
	if err != nil {
		t.Fatal(err)
	}

	var portBuf[4]byte
	binary.BigEndian.PutUint16(portBuf[:], 1234)
	sip := net.ParseIP("1.2.3.4").To4()
	dip := net.ParseIP("5.6.7.8").To4()
	s.Map[string(append(sip, portBuf[:]...))] = dip
	err = s.Update()
	t.Log(err)
}

/*
table ip nat {
        map pmptcp_ip {
                type ipv4_addr . inet_service : ipv4_addr
        }
}
*/
func TestMapIpPortToPort(t *testing.T) {
	c := &Conn{}
	s, err := c.NewSet("nat","pmptcp_port")
	if err != nil {
		t.Fatal(err)
	}

	var portBuf[4]byte
	var portBuf2[2]byte

	binary.BigEndian.PutUint16(portBuf[:], 1234)
	binary.BigEndian.PutUint16(portBuf2[:], 1235)

	sip := net.ParseIP("1.2.3.4").To4()
	s.Map[string(append(sip, portBuf[:]...))] = portBuf2[:]
	err = s.Update()
	t.Log(err)
}
