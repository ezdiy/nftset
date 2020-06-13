package nftset

import (
	"bytes"
	"errors"
	"github.com/google/nftables"
)

type Set struct {
	*Conn
	*nftables.Set
	Map map[string][]byte			// The to-be contents of the set until Update() makes it so
	currentMap map[string][]byte	// The current contents of the set. Used for delta-update.
}

type Conn struct {
	nftables.Conn
}

// Open an existing set 'name', and initialize it to empty.
func (c *Conn) NewSet(table, name string) (*Set, error) {
	tabs, err := c.ListTables()
	if err != nil {
		return nil, err
	}
	for _, tab := range tabs {
		if tab.Name == table || table == "" {
			s, err := c.GetSetByName(tab, name)
			if s == nil {
				// TODO: how to inspect netlink errors? Seems we're getting back only fmt.wrapErr
				if table == "" {
					continue
				}
				return nil, err
			}
			return &Set{
				Conn: c,
				Set: s,
				Map: make(map[string][]byte),
			}, nil
		}
	}
	return nil, errors.New("table or set not found")
}

// Somewhat arbitrary limit of what netlink can handle per one call.
// TODO: fix this in google's nftables by tracking batch size appropriately and auto-flush on overflow
var MaxUpdate = 512

func min(a,b int) int {
	if a < b {
		return a
	}
	return b
}

// Update the kernel nft set to to contents of Map[].
func (s *Set) Update() (err error) {
	var list []nftables.SetElement
	if s.currentMap != nil {
		// compare new map to old snapshot, and collect removed entries
		for k, _ := range s.currentMap {
			if _, exists := s.Map[k]; !exists {
				list = append(list, nftables.SetElement{Key: []byte(k)})
			}
		}
		for len(list) > 0 {
			limit := min(len(list), MaxUpdate)
			if err = s.SetDeleteElements(s.Set, list[:limit]); err != nil {
				return
			}
			list = list[limit:]
		}
	}
	newMap := make(map[string][]byte)
	// now compare old snapshot to new, and note entries that were created or changed
	for k, newV := range s.Map {
		newMap[k] = newV
		var oldV []byte
		var oldExists bool
		if s.currentMap != nil {
			oldV, oldExists = s.currentMap[k]
		}
		if !oldExists || !bytes.Equal(newV, oldV) {
			list = append(list, nftables.SetElement{Key:[]byte(k), Val:newV})
		}
	}
	for len(list) > 0 {
		limit := min(len(list), MaxUpdate)
		if err = s.SetAddElements(s.Set, list[:limit]); err != nil {
			return
		}
		list = list[limit:]
	}
	err = s.Flush()
	if err == nil {
		s.currentMap = newMap
	}
	return
}

