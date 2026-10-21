// Package edge carries agent traffic between platforms (D3, D11, D12). The
// relay takes a stream from the local platform, opens mutual TLS to the
// destination peer's edge (exact EDGE SPIFFE ID) and writes one
// length-prefixed admission frame; everything after it is the agents' own
// end-to-end TLS, copied without being opened. The edge reads that frame,
// asks the adapter runtime to decide (ADMIT), answers with one response frame
// and, when allowed, hands the stream to the local platform until the
// admission deadline. The bridge never verifies tokens or decides trust.
//
// Local stream sockets (platform side, peer-UID checked):
//   - egress: the platform writes one frame with a live-admission/v3
//     admission frame, reads one response frame, then copies bytes if the
//     response is ALLOW;
//   - ingress: the bridge writes one frame with a ptpan-ingress/1 header
//     (schemas/local-ingress-v1.json), then copies bytes.
package edge

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxFrameBytes bounds one admission or response frame.
const MaxFrameBytes = 8 << 10

func WriteFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > MaxFrameBytes {
		return errors.New("frame size")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return nil, errors.New("frame size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
