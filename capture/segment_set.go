package capture

import (
	"net"

	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type MacInt = uint64

type SegmentSet struct {
	segmentSet map[MacInt]string
}

func (s *SegmentSet) Lookup(key MacInt) bool {
	_, found := s.segmentSet[key]
	return found
}

func (s *SegmentSet) OnSegmentChange(segments []net.HardwareAddr) {
	newSegmentSet := map[MacInt]string{}
	for _, segment := range segments {
		newSegmentSet[Mac2Uint64(segment)] = segment.String()
	}

	var appending []string
	for key, mac := range newSegmentSet {
		if _, ok := s.segmentSet[key]; !ok {
			appending = append(appending, mac)
		}
	}
	if appending != nil {
		log.Info("Appending", appending)
	}

	var removing []string
	for key, mac := range s.segmentSet {
		if _, ok := newSegmentSet[key]; !ok {
			removing = append(removing, mac)
		}
	}
	if removing != nil {
		log.Info("Removing", removing)
	}

	s.segmentSet = newSegmentSet
}

func NewSegmentSet() *SegmentSet {
	return &SegmentSet{map[MacInt]string{}}
}
