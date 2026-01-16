package terminator

import (
	"encoding/binary"
	"io"

	"protohytale"
	"quic-terminator/debug"
)

// copyStreamParsed copies data while parsing and logging Hytale packets.
// Used in debug mode to inspect protocol traffic.
func (s *session) copyStreamParsed(dst io.Writer, src io.Reader, fromClient bool) (int64, error) {
	reader := protohytale.NewPacketReader(src)
	var total int64
	var headerBuf [8]byte
	var logged int
	limit := s.packetLimit

	dir := "(C->S)"
	if !fromClient {
		dir = "(S->C)"
	}

	for {
		pkt, err := reader.ReadPacket()
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			debug.Printf("[packet] %s parse error: %v", dir, err)
			return total, err
		}

		// Log packet (only if under limit, 0 = unlimited)
		if limit == 0 || logged < limit {
			logged++
			name := protohytale.PacketName(pkt.ID)
			if name != "" {
				debug.Printf("[packet] %s %s (0x%08X) %d bytes", dir, name, pkt.ID, len(pkt.Data))
			} else {
				debug.Printf("[packet] %s 0x%08X %d bytes", dir, pkt.ID, len(pkt.Data))
			}

			// Extra details for Connect packet
			if pkt.ID == protohytale.PacketConnect && fromClient {
				if conn, err := protohytale.ParseConnectPacket(pkt); err == nil {
					debug.Printf("[packet] %s   user=%s uuid=%s", dir, conn.Username, conn.UUIDString())
				}
			}
		}

		// Forward packet (ALWAYS, regardless of logging)
		binary.LittleEndian.PutUint32(headerBuf[0:4], uint32(len(pkt.Data)))
		binary.LittleEndian.PutUint32(headerBuf[4:8], pkt.ID)

		if _, err := dst.Write(headerBuf[:]); err != nil {
			return total, err
		}
		n, err := dst.Write(pkt.Data)
		total += int64(8 + n)
		if err != nil {
			return total, err
		}
	}
}
