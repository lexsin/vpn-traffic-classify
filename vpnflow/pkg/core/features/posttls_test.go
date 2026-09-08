package features

import (
	"testing"
	"time"

	"vpnflow/pkg/model"
)

func tlsTestRecord(dir int, contentType uint8, handshakeType uint8, length uint16, ms int) model.TLSRecord {
	return model.TLSRecord{
		Timestamp:     time.Unix(0, int64(ms)*int64(time.Millisecond)),
		Direction:     dir,
		ContentType:   contentType,
		HandshakeType: handshakeType,
		RecordLength:  length,
	}
}

func TestPostTLSPayloadRecordsTLS12StartsAtFirstAppData(t *testing.T) {
	flow := &model.Flow{
		ClientHelloSize: 120,
		TLSVersion:      model.TLSVersion12,
		Records: []model.TLSRecord{
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeHandshake, model.TLSHandshakeClientHello, 120, 1),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeHandshake, model.TLSHandshakeServerHello, 90, 2),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeHandshake, model.TLSHandshakeCertificate, 1400, 3),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 80, 4),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeAppData, 0, 300, 5),
		},
	}

	records := postTLSPayloadRecords(flow)
	if len(records) != 2 {
		t.Fatalf("post TLS 1.2 records=%d, want 2", len(records))
	}
	if records[0].RecordLength != 80 || records[0].Direction != model.DirectionUplink {
		t.Fatalf("first post TLS 1.2 record=%+v, want uplink AppData length 80", records[0])
	}
}

func TestPostTLSPayloadRecordsTLS13SkipsProtectedHandshake(t *testing.T) {
	flow := &model.Flow{
		ClientHelloSize: 120,
		TLSVersion:      model.TLSVersion13,
		Records: []model.TLSRecord{
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeHandshake, model.TLSHandshakeClientHello, 120, 1),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeHandshake, model.TLSHandshakeServerHello, 90, 2),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeAppData, 0, 2200, 3),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 40, 4),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 320, 5),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeAppData, 0, 500, 6),
		},
	}

	records := postTLSPayloadRecords(flow)
	if len(records) != 2 {
		t.Fatalf("post TLS 1.3 records=%d, want 2", len(records))
	}
	if records[0].RecordLength != 320 || records[1].RecordLength != 500 {
		t.Fatalf("post TLS 1.3 lengths=%d,%d, want 320,500", records[0].RecordLength, records[1].RecordLength)
	}
}

func TestExtractPostTLSPayloadReadyRequiresThreeRecords(t *testing.T) {
	flow := &model.Flow{
		ClientHelloSize: 120,
		TLSVersion:      model.TLSVersion12,
		Records: []model.TLSRecord{
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeHandshake, model.TLSHandshakeClientHello, 120, 1),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeHandshake, model.TLSHandshakeServerHello, 90, 2),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 80, 4),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeAppData, 0, 300, 5),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 600, 8),
		},
	}

	row := Extract(flow, "sample.pcap", "trojan")
	if row.PostTLSPayloadReady != 1 || row.PostTLSActualAppDataCount != 3 {
		t.Fatalf("payload readiness=%d count=%d, want 1 and 3", row.PostTLSPayloadReady, row.PostTLSActualAppDataCount)
	}
	if row.PostTLSAppDataLen[0] != 80 || row.PostTLSAppDataDir[0] != 1 || row.PostTLSAppDataLen[2] != 600 {
		t.Fatalf("unexpected post TLS sequence: len=%v dir=%v", row.PostTLSAppDataLen, row.PostTLSAppDataDir)
	}
	if row.PostTLSAppDataIAT[1] != 0.001 || row.PostTLSAppDataIAT[2] != 0.003 {
		t.Fatalf("unexpected post TLS IAT: %v", row.PostTLSAppDataIAT)
	}
}
func TestExtractPostTLSShapeExcludesHandshakePackets(t *testing.T) {
	flow := &model.Flow{
		ClientHelloSize: 120,
		TLSVersion:      model.TLSVersion12,
		Records: []model.TLSRecord{
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeHandshake, model.TLSHandshakeClientHello, 120, 1),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeHandshake, model.TLSHandshakeServerHello, 90, 2),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 160, 4),
			tlsTestRecord(model.DirectionDownlink, model.TLSContentTypeAppData, 0, 260, 5),
			tlsTestRecord(model.DirectionUplink, model.TLSContentTypeAppData, 0, 140, 7),
		},
		Packets: []model.PacketInfo{
			{Timestamp: time.Unix(0, int64(time.Millisecond)), Direction: model.DirectionUplink, IPLen: 60},
			{Timestamp: time.Unix(0, 2*int64(time.Millisecond)), Direction: model.DirectionDownlink, IPLen: 1000, PayloadLen: 900},
			{Timestamp: time.Unix(0, 4*int64(time.Millisecond)), Direction: model.DirectionUplink, IPLen: 200, PayloadLen: 160},
			{Timestamp: time.Unix(0, 5*int64(time.Millisecond)), Direction: model.DirectionDownlink, IPLen: 300, PayloadLen: 260},
			{Timestamp: time.Unix(0, 7*int64(time.Millisecond)), Direction: model.DirectionUplink, IPLen: 180, PayloadLen: 140},
		},
	}

	row := Extract(flow, "sample.pcap", "trojan")
	shape := row.PostTLSShape
	if shape.TotalPackets != 3 || shape.TotalPayloadBytes != 560 {
		t.Fatalf("post TLS shape packets=%d payload=%d, want 3 and 560", shape.TotalPackets, shape.TotalPayloadBytes)
	}
	if shape.PktSize[0] != 200 || shape.PktSize[1] != 300 || shape.PktSize[2] != 180 {
		t.Fatalf("post TLS packet sequence=%v, want [200 300 180]", shape.PktSize)
	}
	if shape.PayloadPktSize[0] != 160 || shape.PayloadPktSize[1] != 260 || shape.PayloadPktSize[2] != 140 {
		t.Fatalf("post TLS payload sequence=%v, want [160 260 140]", shape.PayloadPktSize)
	}
	if shape.PktIAT[1] != 0.001 || shape.PktIAT[2] != 0.002 || shape.FlowDuration != 0.003 {
		t.Fatalf("post TLS IAT=%v duration=%v, want 0.001, 0.002, 0.003", shape.PktIAT, shape.FlowDuration)
	}
}
