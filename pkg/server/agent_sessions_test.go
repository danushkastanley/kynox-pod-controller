package server

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pb "pod-controller/pkg/telemetry"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestConnectAgentRequiresCurrentSessionForReconnect(t *testing.T) {
	server := &TelemetryServer{agents: make(map[string]*ConnectedAgent), maxAgents: 2}
	request := &pb.ConnectRequest{AgentId: "agent-a", NodeName: "node-a", PodName: "pod-a"}

	first, err := server.ConnectAgent(context.Background(), request)
	if err != nil {
		t.Fatalf("initial connect failed: %v", err)
	}
	if len(first.SessionId) != encodedSessionIDBytes {
		t.Fatalf("session length = %d, want %d", len(first.SessionId), encodedSessionIDBytes)
	}

	if _, err := server.ConnectAgent(context.Background(), request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reconnect without metadata code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		AgentIDMetadataKey, request.AgentId,
		SessionIDMetadataKey, first.SessionId,
	))
	second, err := server.ConnectAgent(ctx, request)
	if err != nil {
		t.Fatalf("authenticated reconnect failed: %v", err)
	}
	if first.SessionId == second.SessionId {
		t.Fatal("reconnect reused the previous session")
	}
}

func TestConnectAgentValidatesIdentitiesAndCapacity(t *testing.T) {
	server := &TelemetryServer{agents: make(map[string]*ConnectedAgent), maxAgents: 1}

	tooLong := strings.Repeat("a", maxAgentIDBytes+1)
	if _, err := server.ConnectAgent(context.Background(), &pb.ConnectRequest{AgentId: tooLong}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized agent code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
	if _, err := server.ConnectAgent(context.Background(), &pb.ConnectRequest{AgentId: "agent-a"}); err != nil {
		t.Fatalf("first connect failed: %v", err)
	}
	if _, err := server.ConnectAgent(context.Background(), &pb.ConnectRequest{AgentId: "agent-b"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("capacity code = %v, want %v", status.Code(err), codes.ResourceExhausted)
	}
}

func TestStreamEventsRequiresMetadataBeforeReadingEvents(t *testing.T) {
	server := &TelemetryServer{agents: make(map[string]*ConnectedAgent)}
	stream := &testTelemetryStream{ctx: context.Background()}

	err := server.StreamEvents(stream)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
	if stream.recvCalls != 0 {
		t.Fatalf("Recv called %d times before authentication", stream.recvCalls)
	}
}

func TestStreamEventsAcceptsActiveMetadataSession(t *testing.T) {
	sessionID, err := generateSessionID()
	if err != nil {
		t.Fatalf("generate session: %v", err)
	}
	server := &TelemetryServer{agents: map[string]*ConnectedAgent{
		"agent-a": {AgentID: "agent-a", SessionID: sessionID, LastSeen: time.Now()},
	}}
	stream := &testTelemetryStream{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			AgentIDMetadataKey, "agent-a",
			SessionIDMetadataKey, sessionID,
		)),
	}

	if err := server.StreamEvents(stream); err != nil {
		t.Fatalf("active stream failed: %v", err)
	}
	if stream.recvCalls != 1 {
		t.Fatalf("Recv called %d times, want 1", stream.recvCalls)
	}
}

func TestBindEventToAgentOverridesUntrustedContext(t *testing.T) {
	event := &pb.SecurityEvent{ContainerContext: map[string]string{"agent_id": "victim"}}
	bindEventToAgent(event, "authenticated-agent")

	if got := event.ContainerContext["agent_id"]; got != "authenticated-agent" {
		t.Fatalf("bound agent = %q, want authenticated-agent", got)
	}
}

type testTelemetryStream struct {
	ctx       context.Context
	recvCalls int
	sent      []*pb.EventResponse
}

func (s *testTelemetryStream) Send(response *pb.EventResponse) error {
	s.sent = append(s.sent, response)
	return nil
}

func (s *testTelemetryStream) Recv() (*pb.SecurityEvent, error) {
	s.recvCalls++
	return nil, io.EOF
}

func (s *testTelemetryStream) SetHeader(metadata.MD) error  { return nil }
func (s *testTelemetryStream) SendHeader(metadata.MD) error { return nil }
func (s *testTelemetryStream) SetTrailer(metadata.MD)       {}
func (s *testTelemetryStream) Context() context.Context     { return s.ctx }
func (s *testTelemetryStream) SendMsg(interface{}) error    { return nil }
func (s *testTelemetryStream) RecvMsg(interface{}) error    { return io.EOF }
