package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExecuteWorkflowPreservesLog(t *testing.T) {
	t.Cleanup(func() { _ = os.RemoveAll(artifactDir) })

	result, err := executeWorkflow(10)
	if err != nil {
		t.Fatalf("executeWorkflow() error = %v", err)
	}
	if result.EventCount != 10 {
		t.Fatalf("event count = %d, want 10", result.EventCount)
	}
	if result.PlainHash == result.EncryptedHash {
		t.Fatal("plain and encrypted hashes unexpectedly match")
	}
	if !result.IntegrityPreserved || result.PlainHash != result.DecryptedHash {
		t.Fatal("decrypted log does not preserve the original")
	}

	data, err := os.ReadFile(filepath.Join(artifactDir, logFile))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal log: %v", err)
	}
	for _, event := range log.Events {
		p := payload{
			ID: event.ID, Timestamp: event.Timestamp, Type: event.Type,
			ActorUID: event.ActorUID, StudentUID: event.StudentUID,
			CourseUID: event.CourseUID, Operation: event.Operation,
		}
		payloadBytes, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		if event.PayloadHash != sha256Hex(payloadBytes) {
			t.Fatalf("invalid payload hash for event %s", event.ID)
		}
	}
}
