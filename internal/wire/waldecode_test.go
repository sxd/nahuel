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
	"strings"
	"testing"
)

func TestWALStreamDecoderDecodesRecordMetadata(t *testing.T) {
	pageLSN := uint64(0x0000000200000000)
	body := makeTestWALBlockRecordBody(walRelFileLocator{SpcOID: 1663, DBOID: 5, RelNumber: 1259}, 42, 8, 4)
	record := makeTestWALRecord(10, 0x00, 42, 0x0000000100000010, body)
	wal := makeTestWALPage(pageLSN, record)

	decoder := newWALStreamDecoder()
	records := decoder.Feed(pageLSN, wal)
	if len(records) != 1 {
		t.Fatalf("expected one WAL record, got %d", len(records))
	}

	rec := records[0]
	if rec.LSN != pageLSN+walShortPageHeaderSize {
		t.Fatalf("expected record LSN %s, got %s", formatLSN(pageLSN+walShortPageHeaderSize), formatLSN(rec.LSN))
	}
	if rec.Rmgr != "Heap" {
		t.Fatalf("expected Heap rmgr, got %q", rec.Rmgr)
	}
	if rec.XID != 42 {
		t.Fatalf("expected xid 42, got %d", rec.XID)
	}
	if rec.MainDataLen != 4 {
		t.Fatalf("expected main data len 4, got %d", rec.MainDataLen)
	}
	if rec.BlockDataBytes != 8 {
		t.Fatalf("expected block data bytes 8, got %d", rec.BlockDataBytes)
	}
	if len(rec.Blocks) != 1 {
		t.Fatalf("expected one block ref, got %d", len(rec.Blocks))
	}
	if !rec.Blocks[0].HasRel || rec.Blocks[0].Rel.RelNumber != 1259 || rec.Blocks[0].BlockNo != 42 {
		t.Fatalf("unexpected block ref: %#v", rec.Blocks[0])
	}
}

func TestParserAppendsWALRecordSummaryToXLogData(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	pageLSN := uint64(0x0000000300000000)
	body := makeTestWALBlockRecordBody(walRelFileLocator{SpcOID: 1663, DBOID: 5, RelNumber: 2608}, 7, 8, 4)
	record := makeTestWALRecord(11, 0x20, 84, 0x0000000200000000, body)
	wal := makeTestWALPage(pageLSN, record)
	payload := makeStructuredXLogDataPayload(pageLSN, wal)

	events := parser.Feed(Chunk{
		PID:       999,
		ConnPtr:   77,
		Direction: DirectionServerToClient,
		API:       APISecureWrite,
		Data:      makeRegularMessage('d', payload),
	})
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].MessageType != "XLogData" {
		t.Fatalf("expected XLogData, got %s", events[0].MessageType)
	}
	for _, needle := range []string{"records=1", "Btree", "xid=84", "blocks=1", "main=4", "rel=1663/5/2608", "blk=7"} {
		if !strings.Contains(events[0].Summary, needle) {
			t.Fatalf("expected summary to contain %q, got %q", needle, events[0].Summary)
		}
	}
}

func TestParserDecodesPartialWALRecordFromTruncatedXLogData(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	pageLSN := uint64(0x0000000400000000)
	body := makeTestWALBlockRecordBody(walRelFileLocator{SpcOID: 1663, DBOID: 5, RelNumber: 5000}, 9, 64, 96)
	record := makeTestWALRecord(10, 0x00, 123, 0x0000000300000000, body)
	wal := makeTestWALPage(pageLSN, record)
	payload := makeStructuredXLogDataPayload(pageLSN, wal)
	message := makeRegularMessage('d', payload)
	captured := 5 + 25 + walShortPageHeaderSize + walRecordHeaderSize + 22
	if captured >= len(message) {
		t.Fatalf("test message unexpectedly short: captured=%d len=%d", captured, len(message))
	}

	events := parser.Feed(Chunk{
		PID:         1001,
		ConnPtr:     88,
		Direction:   DirectionServerToClient,
		API:         APISecureWrite,
		Data:        append([]byte(nil), message[:captured]...),
		Truncated:   true,
		CapturedLen: uint32(captured),
		TotalLen:    uint32(len(message)),
	})
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].MessageType != "XLogData" {
		t.Fatalf("expected XLogData, got %s", events[0].MessageType)
	}
	for _, needle := range []string{"records=1", "Heap", "partial", "xid=123", "blocks=1", "main=96", "blkdata=64"} {
		if !strings.Contains(events[0].Summary, needle) {
			t.Fatalf("expected summary to contain %q, got %q", needle, events[0].Summary)
		}
	}
}

func makeTestWALPage(pageLSN uint64, records ...[]byte) []byte {
	page := make([]byte, walShortPageHeaderSize)
	binary.LittleEndian.PutUint16(page[0:2], walPageMagic)
	binary.LittleEndian.PutUint16(page[2:4], 0)
	binary.LittleEndian.PutUint32(page[4:8], 1)
	binary.LittleEndian.PutUint64(page[8:16], pageLSN)
	binary.LittleEndian.PutUint32(page[16:20], 0)
	for idx, record := range records {
		page = append(page, record...)
		if idx == len(records)-1 {
			continue
		}
		for len(page)%walAlignment != 0 {
			page = append(page, 0)
		}
	}
	return page
}

func makeTestWALRecord(rmgrID uint8, info uint8, xid uint32, prev uint64, body []byte) []byte {
	record := make([]byte, walRecordHeaderSize+len(body))
	binary.LittleEndian.PutUint32(record[0:4], uint32(len(record)))
	binary.LittleEndian.PutUint32(record[4:8], xid)
	binary.LittleEndian.PutUint64(record[8:16], prev)
	record[16] = info
	record[17] = rmgrID
	binary.LittleEndian.PutUint32(record[20:24], 0)
	copy(record[24:], body)
	return record
}

func makeTestWALBlockRecordBody(rel walRelFileLocator, blockNo uint32, blockDataLen int, mainDataLen int) []byte {
	body := make([]byte, 0, walBlockHeaderSize+walRelFileLocatorSize+walBlockNumberSize+walRecordMainDataShortHeader+blockDataLen+mainDataLen)
	body = append(body, 0)
	body = append(body, walBlockHasData)
	dataLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(dataLen, uint16(blockDataLen))
	body = append(body, dataLen...)
	loc := make([]byte, walRelFileLocatorSize)
	binary.LittleEndian.PutUint32(loc[0:4], rel.SpcOID)
	binary.LittleEndian.PutUint32(loc[4:8], rel.DBOID)
	binary.LittleEndian.PutUint32(loc[8:12], rel.RelNumber)
	body = append(body, loc...)
	blk := make([]byte, 4)
	binary.LittleEndian.PutUint32(blk, blockNo)
	body = append(body, blk...)
	if mainDataLen > 0 && mainDataLen < 256 {
		body = append(body, walBlockIDDataShort, byte(mainDataLen))
	}
	for i := 0; i < blockDataLen; i++ {
		body = append(body, 0x80)
	}
	for i := 0; i < mainDataLen; i++ {
		body = append(body, 0x90)
	}
	return body
}

func makeStructuredXLogDataPayload(startLSN uint64, wal []byte) []byte {
	payload := make([]byte, 1+8+8+8+len(wal))
	payload[0] = 'w'
	binary.BigEndian.PutUint64(payload[1:9], startLSN)
	binary.BigEndian.PutUint64(payload[9:17], startLSN+uint64(len(wal)))
	binary.BigEndian.PutUint64(payload[17:25], 0)
	copy(payload[25:], wal)
	return payload
}
