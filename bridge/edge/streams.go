package edge

import (
	"io"
	"net"
	"sync"
	"time"
)

// Streams tracks open agent streams so a revoke, a suspension or a removal
// closes them at once (D3).
type Streams struct {
	mu   sync.Mutex
	next uint64
	open map[uint64]stream
}

type stream struct {
	relationshipID string
	peerEdgeID     string
	conns          []net.Conn
}

func (s *Streams) add(relationshipID, peerEdgeID string, conns ...net.Conn) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		s.open = map[uint64]stream{}
	}
	s.next++
	s.open[s.next] = stream{relationshipID: relationshipID, peerEdgeID: peerEdgeID, conns: conns}
	return s.next
}

func (s *Streams) remove(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, id)
}

// Close closes every stream of a relationship and/or of one peer edge.
// It returns how many streams it closed.
func (s *Streams) Close(relationshipID, peerEdgeID *string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	closed := 0
	for id, open := range s.open {
		if (relationshipID != nil && open.relationshipID == *relationshipID) ||
			(peerEdgeID != nil && open.peerEdgeID == *peerEdgeID) {
			for _, conn := range open.conns {
				_ = conn.Close()
			}
			delete(s.open, id)
			closed++
		}
	}
	return closed
}

// Count is the number of open streams.
func (s *Streams) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.open)
}

// pipe copies both ways until either side ends or the deadline passes, then
// closes both. The bytes are the agents' own TLS and are never inspected.
func (s *Streams) pipe(relationshipID, peerEdgeID string, a, b net.Conn, deadline time.Time) {
	id := s.add(relationshipID, peerEdgeID, a, b)
	defer s.remove(id)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
