// Copyright 2026 Jonathan Gonzalez V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wire

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	defaultWALPageSize             = 8192
	maxWALDecoderBufferBytes       = 256 << 10
	maxWALRecordsPerMessage        = 3
	maxWALRecordRefsInSummary      = 2
	walAlignment                   = 8
	walPageMagic                   = 0xD11F
	walPageFlagContRecord          = 0x0001
	walPageFlagLongHeader          = 0x0002
	walPageAllFlags                = 0x0007
	walShortPageHeaderSize         = 24
	walLongPageHeaderSize          = 40
	walRecordHeaderSize            = 24
	walBlockHeaderSize             = 4
	walBlockImageHeaderSize        = 5
	walBlockCompressHeaderSize     = 2
	walRelFileLocatorSize          = 12
	walBlockNumberSize             = 4
	walRecordMainDataShortHeader   = 2
	walRecordMainDataLongHeader    = 5
	walRecordOriginHeaderSize      = 3
	walRecordTopLevelXIDHeaderSize = 5
	walMaxBlockID                  = 32
	walBlockIDDataShort            = 255
	walBlockIDDataLong             = 254
	walBlockIDOrigin               = 253
	walBlockIDTopLevelXID          = 252
	walBlockHasImage               = 0x10
	walBlockHasData                = 0x20
	walBlockWillInit               = 0x40
	walBlockSameRel                = 0x80
	walBlockForkMask               = 0x0F
	walBkpImageHasHole             = 0x01
	walBkpImageCompressPGLZ        = 0x04
	walBkpImageCompressLZ4         = 0x08
	walBkpImageCompressZSTD        = 0x10
)

var walRmgrNames = []string{
	"XLOG",
	"Transaction",
	"Storage",
	"CLOG",
	"Database",
	"Tablespace",
	"MultiXact",
	"RelMap",
	"Standby",
	"Heap2",
	"Heap",
	"Btree",
	"Hash",
	"Gin",
	"Gist",
	"Sequence",
	"SPGist",
	"BRIN",
	"CommitTs",
	"ReplicationOrigin",
	"Generic",
	"LogicalMessage",
	"XLOG2",
}

type walStreamDecoder struct {
	pageSize    int
	bufferStart uint64
	buffer      []byte
	synced      bool
}

type walPageHeader struct {
	info     uint16
	remLen   uint32
	headerSz int
	pageSize int
}

type walRecordHeader struct {
	TotalLen uint32
	XID      uint32
	Prev     uint64
	Info     uint8
	RmgrID   uint8
	CRC      uint32
}

type walRelFileLocator struct {
	SpcOID    uint32
	DBOID     uint32
	RelNumber uint32
}

type walBlockRef struct {
	ID       uint8
	Fork     string
	BlockNo  uint32
	DataLen  uint16
	ImageLen uint16
	HasData  bool
	HasImage bool
	WillInit bool
	HasRel   bool
	Rel      walRelFileLocator
}

type walRecordSummary struct {
	LSN            uint64
	TotalLen       uint32
	XID            uint32
	Prev           uint64
	RmgrID         uint8
	Rmgr           string
	Info           uint8
	MainDataLen    int
	BlockDataBytes int
	FPIBytes       int
	Blocks         []walBlockRef
	OriginID       *uint16
	TopLevelXID    *uint32
	Partial        bool
}

func newWALStreamDecoder() *walStreamDecoder {
	return &walStreamDecoder{pageSize: defaultWALPageSize}
}

func (d *walStreamDecoder) Feed(startLSN uint64, wal []byte) []walRecordSummary {
	if len(wal) == 0 {
		return nil
	}
	if d.pageSize <= 0 {
		d.pageSize = defaultWALPageSize
	}

	d.append(startLSN, wal)
	records, consumed := d.consume(false)
	d.trimConsumed(consumed)
	return records
}

func (d *walStreamDecoder) DecodePreview(startLSN uint64, wal []byte) []walRecordSummary {
	if len(wal) == 0 {
		return nil
	}
	tmp := walStreamDecoder{pageSize: d.pageSize, bufferStart: d.bufferStart, synced: d.synced}
	if tmp.pageSize <= 0 {
		tmp.pageSize = defaultWALPageSize
	}
	if len(d.buffer) > 0 {
		tmp.bufferStart = d.bufferStart
		tmp.buffer = append([]byte(nil), d.buffer...)
	}
	tmp.append(startLSN, wal)
	records, _ := tmp.consume(true)
	return records
}

func (d *walStreamDecoder) append(startLSN uint64, wal []byte) {
	if len(wal) == 0 {
		return
	}
	if len(d.buffer) == 0 {
		if d.bufferStart != startLSN {
			d.synced = false
		}
		d.bufferStart = startLSN
		d.buffer = append([]byte(nil), wal...)
		return
	}

	bufferEnd := d.bufferStart + uint64(len(d.buffer))
	switch {
	case startLSN == bufferEnd:
		d.buffer = append(d.buffer, wal...)
	case startLSN > bufferEnd:
		d.bufferStart = startLSN
		d.buffer = append(d.buffer[:0], wal...)
		d.synced = false
	case startLSN >= d.bufferStart:
		overlap := int(bufferEnd - startLSN)
		if overlap < len(wal) {
			d.buffer = append(d.buffer, wal[overlap:]...)
		}
	default:
		d.bufferStart = startLSN
		d.buffer = append([]byte(nil), wal...)
		d.synced = false
	}

	if len(d.buffer) > maxWALDecoderBufferBytes {
		keep := min(len(d.buffer), d.pageSize*2)
		d.bufferStart += uint64(len(d.buffer) - keep)
		d.buffer = append([]byte(nil), d.buffer[len(d.buffer)-keep:]...)
	}
}

func (d *walStreamDecoder) trimConsumed(consumed int) {
	if consumed <= 0 {
		return
	}
	if consumed >= len(d.buffer) {
		d.bufferStart += uint64(consumed)
		d.buffer = nil
		return
	}
	d.bufferStart += uint64(consumed)
	d.buffer = append([]byte(nil), d.buffer[consumed:]...)
}

func (d *walStreamDecoder) consume(allowPartial bool) ([]walRecordSummary, int) {
	if len(d.buffer) == 0 {
		return nil, 0
	}

	var records []walRecordSummary
	offset := 0
	for len(records) < maxWALRecordsPerMessage && offset < len(d.buffer) {
		lsn := d.bufferStart + uint64(offset)
		pageOff := int(lsn % uint64(d.pageSize))

		if pageOff == 0 {
			hdr, ok := parseWALPageHeader(d.buffer[offset:], lsn, d.pageSize)
			if !ok {
				break
			}
			d.synced = true
			if hdr.pageSize > 0 && hdr.pageSize != d.pageSize {
				d.pageSize = hdr.pageSize
			}
			offset += hdr.headerSz
			if hdr.remLen > 0 {
				pageRemaining := d.pageSize - hdr.headerSz
				if pageRemaining <= 0 || len(d.buffer)-offset < pageRemaining {
					break
				}
				skip := min(pageRemaining, int(hdr.remLen))
				offset += skip
				continue
			}
			continue
		}

		if offset == 0 && !d.synced {
			skip := d.pageSize - pageOff
			if skip <= 0 || skip > len(d.buffer)-offset {
				break
			}
			offset += skip
			continue
		}

		aligned := alignUp64(lsn, walAlignment)
		if aligned != lsn {
			pad := int(aligned - lsn)
			if pad <= 0 || pad > len(d.buffer)-offset {
				break
			}
			offset += pad
			continue
		}

		record, consumed, ok, needMore := parseOneWALRecordFromBuffer(d.buffer[offset:], lsn, d.pageSize, allowPartial)
		if needMore && !allowPartial {
			break
		}
		if !ok {
			d.synced = false
			skip := d.pageSize - int(lsn%uint64(d.pageSize))
			if skip <= 0 || skip > len(d.buffer)-offset {
				break
			}
			offset += skip
			continue
		}
		d.synced = true
		records = append(records, record)
		if allowPartial && record.Partial {
			break
		}
		if consumed <= 0 {
			break
		}
		offset += consumed
	}

	return records, offset
}

func parseOneWALRecordFromBuffer(buf []byte, recordLSN uint64, pageSize int, allowPartial bool) (walRecordSummary, int, bool, bool) {
	headerBytes, _, headerComplete, ok := collectWALLogicalBytes(buf, recordLSN, pageSize, walRecordHeaderSize, allowPartial)
	if !ok {
		return walRecordSummary{}, 0, false, false
	}
	if !headerComplete {
		return walRecordSummary{}, 0, false, true
	}

	hdr := parseWALRecordHeader(headerBytes)
	if !plausibleWALRecordHeader(hdr) {
		return walRecordSummary{}, 0, false, false
	}

	recordBytes, consumed, recordComplete, ok := collectWALLogicalBytes(buf, recordLSN, pageSize, int(hdr.TotalLen), allowPartial)
	if !ok {
		return walRecordSummary{}, 0, false, false
	}
	if !recordComplete && !allowPartial {
		return walRecordSummary{}, 0, false, true
	}

	record, ok := parseWALRecordSummary(recordLSN, recordBytes, recordComplete)
	if !ok {
		return walRecordSummary{}, 0, false, false
	}
	return record, consumed, true, false
}

func collectWALLogicalBytes(buf []byte, startLSN uint64, pageSize int, logicalLen int, allowPartial bool) ([]byte, int, bool, bool) {
	if logicalLen <= 0 {
		return nil, 0, true, true
	}

	out := make([]byte, 0, min(logicalLen, len(buf)))
	offset := 0
	lsn := startLSN
	expectContinuation := false
	remaining := logicalLen

	for remaining > 0 {
		pageOff := int(lsn % uint64(pageSize))
		if pageOff == 0 {
			hdr, ok := parseWALPageHeader(buf[offset:], lsn, pageSize)
			if !ok {
				if allowPartial {
					return out, offset, false, true
				}
				return nil, 0, false, false
			}
			if expectContinuation && hdr.remLen == 0 {
				return nil, 0, false, false
			}
			offset += hdr.headerSz
			lsn += uint64(hdr.headerSz)
			pageOff = int(lsn % uint64(pageSize))
			expectContinuation = false
		}

		if offset >= len(buf) {
			return out, offset, false, true
		}

		pageAvail := pageSize - pageOff
		if pageAvail <= 0 {
			return nil, 0, false, false
		}
		take := min(remaining, pageAvail)
		available := len(buf) - offset
		if available < take {
			if !allowPartial {
				return out, offset, false, true
			}
			take = available
		}
		if take <= 0 {
			return out, offset, false, true
		}

		out = append(out, buf[offset:offset+take]...)
		offset += take
		lsn += uint64(take)
		remaining -= take
		if remaining > 0 {
			expectContinuation = true
		}
	}

	return out, offset, true, true
}

func parseWALPageHeader(buf []byte, pageLSN uint64, defaultPageSize int) (walPageHeader, bool) {
	if len(buf) < walShortPageHeaderSize {
		return walPageHeader{}, false
	}
	magic := binary.LittleEndian.Uint16(buf[0:2])
	if magic != walPageMagic {
		return walPageHeader{}, false
	}
	info := binary.LittleEndian.Uint16(buf[2:4])
	if info&^walPageAllFlags != 0 {
		return walPageHeader{}, false
	}
	pageAddr := binary.LittleEndian.Uint64(buf[8:16])
	if pageAddr != pageLSN {
		return walPageHeader{}, false
	}

	hdr := walPageHeader{
		info:     info,
		remLen:   binary.LittleEndian.Uint32(buf[16:20]),
		headerSz: walShortPageHeaderSize,
		pageSize: defaultPageSize,
	}
	if info&walPageFlagLongHeader != 0 {
		if len(buf) < walLongPageHeaderSize {
			return walPageHeader{}, false
		}
		pageSize := int(binary.LittleEndian.Uint32(buf[32:36]))
		if pageSize >= walShortPageHeaderSize && pageSize <= (1<<20) {
			hdr.pageSize = pageSize
		}
		hdr.headerSz = walLongPageHeaderSize
	}
	if hdr.pageSize < hdr.headerSz {
		return walPageHeader{}, false
	}
	return hdr, true
}

func parseWALRecordHeader(buf []byte) walRecordHeader {
	return walRecordHeader{
		TotalLen: binary.LittleEndian.Uint32(buf[0:4]),
		XID:      binary.LittleEndian.Uint32(buf[4:8]),
		Prev:     binary.LittleEndian.Uint64(buf[8:16]),
		Info:     buf[16],
		RmgrID:   buf[17],
		CRC:      binary.LittleEndian.Uint32(buf[20:24]),
	}
}

func plausibleWALRecordHeader(hdr walRecordHeader) bool {
	if hdr.TotalLen < walRecordHeaderSize || hdr.TotalLen > maxMessageLength {
		return false
	}
	if int(hdr.RmgrID) >= len(walRmgrNames) {
		return false
	}
	return true
}

func parseWALRecordSummary(recordLSN uint64, record []byte, complete bool) (walRecordSummary, bool) {
	if len(record) < walRecordHeaderSize {
		return walRecordSummary{}, false
	}
	hdr := parseWALRecordHeader(record[:walRecordHeaderSize])
	if !plausibleWALRecordHeader(hdr) {
		return walRecordSummary{}, false
	}

	summary := walRecordSummary{
		LSN:      recordLSN,
		TotalLen: hdr.TotalLen,
		XID:      hdr.XID,
		Prev:     hdr.Prev,
		RmgrID:   hdr.RmgrID,
		Rmgr:     walRmgrName(hdr.RmgrID),
		Info:     hdr.Info,
		Partial:  !complete,
	}

	body := record[walRecordHeaderSize:]
	offset := 0
	var lastRel walRelFileLocator
	haveLastRel := false

	for offset < len(body) {
		id := body[offset]
		switch {
		case id <= walMaxBlockID:
			if len(body)-offset < walBlockHeaderSize {
				summary.Partial = true
				return summary, true
			}
			blk := walBlockRef{ID: id}
			blkFlags := body[offset+1]
			blk.Fork = walForkName(blkFlags & walBlockForkMask)
			blk.DataLen = binary.LittleEndian.Uint16(body[offset+2 : offset+4])
			blk.HasData = blkFlags&walBlockHasData != 0
			blk.HasImage = blkFlags&walBlockHasImage != 0
			blk.WillInit = blkFlags&walBlockWillInit != 0
			offset += walBlockHeaderSize

			if blk.HasImage {
				if len(body)-offset < walBlockImageHeaderSize {
					summary.Partial = true
					return summary, true
				}
				blk.ImageLen = binary.LittleEndian.Uint16(body[offset : offset+2])
				bimgInfo := body[offset+4]
				offset += walBlockImageHeaderSize
				if bimgInfo&walBkpImageHasHole != 0 && isCompressedBkpImage(bimgInfo) {
					if len(body)-offset < walBlockCompressHeaderSize {
						summary.Partial = true
						return summary, true
					}
					offset += walBlockCompressHeaderSize
				}
				summary.FPIBytes += int(blk.ImageLen)
			}

			if blkFlags&walBlockSameRel == 0 {
				if len(body)-offset < walRelFileLocatorSize {
					summary.Partial = true
					return summary, true
				}
				blk.Rel = walRelFileLocator{
					SpcOID:    binary.LittleEndian.Uint32(body[offset : offset+4]),
					DBOID:     binary.LittleEndian.Uint32(body[offset+4 : offset+8]),
					RelNumber: binary.LittleEndian.Uint32(body[offset+8 : offset+12]),
				}
				blk.HasRel = true
				lastRel = blk.Rel
				haveLastRel = true
				offset += walRelFileLocatorSize
			} else if haveLastRel {
				blk.Rel = lastRel
				blk.HasRel = true
			}

			if len(body)-offset < walBlockNumberSize {
				summary.Partial = true
				return summary, true
			}
			blk.BlockNo = binary.LittleEndian.Uint32(body[offset : offset+4])
			offset += walBlockNumberSize
			if blk.HasData {
				summary.BlockDataBytes += int(blk.DataLen)
			}
			summary.Blocks = append(summary.Blocks, blk)
		case id == walBlockIDDataShort:
			if len(body)-offset < walRecordMainDataShortHeader {
				summary.Partial = true
				return summary, true
			}
			summary.MainDataLen = int(body[offset+1])
			return summary, true
		case id == walBlockIDDataLong:
			if len(body)-offset < walRecordMainDataLongHeader {
				summary.Partial = true
				return summary, true
			}
			summary.MainDataLen = int(binary.LittleEndian.Uint32(body[offset+1 : offset+5]))
			return summary, true
		case id == walBlockIDOrigin:
			if len(body)-offset < walRecordOriginHeaderSize {
				summary.Partial = true
				return summary, true
			}
			origin := binary.LittleEndian.Uint16(body[offset+1 : offset+3])
			summary.OriginID = &origin
			offset += walRecordOriginHeaderSize
		case id == walBlockIDTopLevelXID:
			if len(body)-offset < walRecordTopLevelXIDHeaderSize {
				summary.Partial = true
				return summary, true
			}
			topXID := binary.LittleEndian.Uint32(body[offset+1 : offset+5])
			summary.TopLevelXID = &topXID
			offset += walRecordTopLevelXIDHeaderSize
		default:
			return summary, true
		}
	}

	return summary, true
}

func formatWALRecordSummaries(records []walRecordSummary, limit int) string {
	if len(records) == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("records=%d", len(records))}
	for idx, record := range records {
		parts = append(parts, fmt.Sprintf("rec%d=%s", idx, formatWALRecordSummary(record)))
	}
	return truncateWALDetail(strings.Join(parts, " "), limit)
}

func formatWALRecordSummary(record walRecordSummary) string {
	parts := []string{
		formatLSN(record.LSN),
		record.Rmgr,
		fmt.Sprintf("info=0x%02x", record.Info),
		fmt.Sprintf("len=%d", record.TotalLen),
		fmt.Sprintf("blocks=%d", len(record.Blocks)),
	}
	if record.Partial {
		parts = append(parts, "partial")
	}
	if record.XID != 0 {
		parts = append(parts, fmt.Sprintf("xid=%d", record.XID))
	}
	if record.MainDataLen > 0 {
		parts = append(parts, fmt.Sprintf("main=%d", record.MainDataLen))
	}
	if record.BlockDataBytes > 0 {
		parts = append(parts, fmt.Sprintf("blkdata=%d", record.BlockDataBytes))
	}
	if record.FPIBytes > 0 {
		parts = append(parts, fmt.Sprintf("fpi=%d", record.FPIBytes))
	}
	if record.OriginID != nil {
		parts = append(parts, fmt.Sprintf("origin=%d", *record.OriginID))
	}
	if record.TopLevelXID != nil {
		parts = append(parts, fmt.Sprintf("topxid=%d", *record.TopLevelXID))
	}
	for idx, block := range record.Blocks[:min(len(record.Blocks), maxWALRecordRefsInSummary)] {
		parts = append(parts, fmt.Sprintf("ref%d=%s", idx, formatWALBlockRef(block)))
	}
	return strings.Join(parts, ",")
}

func formatWALBlockRef(block walBlockRef) string {
	parts := []string{fmt.Sprintf("id=%d", block.ID)}
	if block.HasRel {
		parts = append(parts, fmt.Sprintf("rel=%d/%d/%d", block.Rel.SpcOID, block.Rel.DBOID, block.Rel.RelNumber))
	}
	parts = append(parts, fmt.Sprintf("fork=%s", block.Fork))
	parts = append(parts, fmt.Sprintf("blk=%d", block.BlockNo))
	if block.HasData {
		parts = append(parts, fmt.Sprintf("data=%d", block.DataLen))
	}
	if block.HasImage {
		parts = append(parts, fmt.Sprintf("image=%d", block.ImageLen))
	}
	if block.WillInit {
		parts = append(parts, "init")
	}
	return strings.Join(parts, ":")
}

func walRmgrName(id uint8) string {
	if int(id) < len(walRmgrNames) {
		return walRmgrNames[id]
	}
	return fmt.Sprintf("Rmgr%d", id)
}

func walForkName(fork uint8) string {
	switch fork {
	case 0:
		return "main"
	case 1:
		return "fsm"
	case 2:
		return "vm"
	case 3:
		return "init"
	default:
		return fmt.Sprintf("fork%d", fork)
	}
}

func isCompressedBkpImage(info byte) bool {
	return info&(walBkpImageCompressPGLZ|walBkpImageCompressLZ4|walBkpImageCompressZSTD) != 0
}

func alignUp64(value uint64, align uint64) uint64 {
	if align == 0 {
		return value
	}
	mask := align - 1
	return (value + mask) &^ mask
}

func truncateWALDetail(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}
