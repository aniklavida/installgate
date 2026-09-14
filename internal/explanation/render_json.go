package explanation

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// RenderJSON serializes a DecisionDocument to normalized JSON bytes.
func RenderJSON(doc *DecisionDocument) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("decision document cannot be nil")
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("failed to encode decision document to JSON: %w", err)
	}

	return buf.Bytes(), nil
}

// RenderJSONIndent serializes a DecisionDocument with custom indentation.
func RenderJSONIndent(doc *DecisionDocument, prefix, indent string) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("decision document cannot be nil")
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent(prefix, indent)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("failed to encode decision document to JSON: %w", err)
	}

	return buf.Bytes(), nil
}

// ParseJSON deserializes a DecisionDocument from JSON bytes.
func ParseJSON(data []byte) (*DecisionDocument, error) {
	var doc DecisionDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode JSON decision document: %w", err)
	}
	return &doc, nil
}
