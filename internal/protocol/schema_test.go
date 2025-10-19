package protocol

import (
    "encoding/json"
    "testing"
)

func TestCanonicalizeJSON_SimpleObject(t *testing.T) {
    input := []byte(`{"b":2,"a":1}`)
    output := CanonicalizeJSON(input)
    // Should produce stable ordering
    var result map[string]int
    if err := json.Unmarshal(output, &result); err != nil {
        t.Fatalf("output not valid JSON: %v", err)
    }
    if result["a"] != 1 || result["b"] != 2 {
        t.Fatalf("incorrect values: %v", result)
    }
}

func TestCanonicalizeJSON_NestedStructures(t *testing.T) {
    input := []byte(`{"nested":{"z":3,"a":1},"top":{"b":2}}`)
    output := CanonicalizeJSON(input)
    var result map[string]interface{}
    if err := json.Unmarshal(output, &result); err != nil {
        t.Fatalf("output not valid JSON: %v", err)
    }
    nested, ok := result["nested"].(map[string]interface{})
    if !ok {
        t.Fatalf("nested not a map")
    }
    if nested["a"] != float64(1) || nested["z"] != float64(3) {
        t.Fatalf("nested values incorrect")
    }
}

func TestCanonicalizeJSON_ArrayHandling(t *testing.T) {
    input := []byte(`{"items":[3,1,2]}`)
    output := CanonicalizeJSON(input)
    var result map[string]interface{}
    if err := json.Unmarshal(output, &result); err != nil {
        t.Fatalf("output not valid JSON: %v", err)
    }
    items, ok := result["items"].([]interface{})
    if !ok {
        t.Fatalf("items not an array")
    }
    // Array order should be preserved
    if items[0] != float64(3) || items[1] != float64(1) || items[2] != float64(2) {
        t.Fatalf("array order not preserved: %v", items)
    }
}

func TestCanonicalizeJSON_NullValues(t *testing.T) {
    input := []byte(`{"a":null,"b":1}`)
    output := CanonicalizeJSON(input)
    var result map[string]interface{}
    if err := json.Unmarshal(output, &result); err != nil {
        t.Fatalf("output not valid JSON: %v", err)
    }
    if result["a"] != nil {
        t.Fatalf("null value not preserved")
    }
}

func TestCanonicalizeJSON_UnicodeAndEscapes(t *testing.T) {
    input := []byte(`{"unicode":"你好","escaped":"quote\"here","newline":"line1\nline2"}`)
    output := CanonicalizeJSON(input)
    var result map[string]interface{}
    if err := json.Unmarshal(output, &result); err != nil {
        t.Fatalf("output not valid JSON: %v", err)
    }
    if result["unicode"] != "你好" {
        t.Fatalf("unicode not preserved")
    }
    if result["escaped"] != `quote"here` {
        t.Fatalf("escaped quotes not preserved")
    }
}

func TestCanonicalizeJSON_MalformedInput(t *testing.T) {
    input := []byte(`{invalid json}`)
    output := CanonicalizeJSON(input)
    // Should return input unchanged on error
    if string(output) != string(input) {
        t.Fatalf("expected input to be returned on parse error")
    }
}

func TestCanonicalizeJSON_EmptyObject(t *testing.T) {
    input := []byte(`{}`)
    output := CanonicalizeJSON(input)
    if string(output) != `{}` {
        t.Fatalf("empty object not preserved: %s", output)
    }
}

func TestCanonicalizeJSON_EmptyArray(t *testing.T) {
    input := []byte(`[]`)
    output := CanonicalizeJSON(input)
    if string(output) != `[]` {
        t.Fatalf("empty array not preserved: %s", output)
    }
}

func TestErrStruct_ErrorFormatting(t *testing.T) {
    err := &Err{Code: "test_code", Message: "test message"}
    expected := "test_code: test message"
    if err.Error() != expected {
        t.Fatalf("error format mismatch: got %q, expected %q", err.Error(), expected)
    }
}

func TestErrStruct_ErrorWithEmptyMessage(t *testing.T) {
    err := &Err{Code: "just_code", Message: ""}
    expected := "just_code: "
    if err.Error() != expected {
        t.Fatalf("error format with empty message: got %q", err.Error())
    }
}