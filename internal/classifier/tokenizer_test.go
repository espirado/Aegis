package classifier

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestVocab(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	vocabPath := filepath.Join(dir, "vocab.txt")
	// Minimal vocab for testing
	vocab := "[PAD]\n[UNK]\n[CLS]\n[SEP]\n[MASK]\nhello\nworld\nthe\npatient\n##s\n##ing\n##tion\n,\n.\na\ntest\n"
	os.WriteFile(vocabPath, []byte(vocab), 0644)
	return vocabPath
}

func TestNewWordPieceTokenizer(t *testing.T) {
	vocabPath := writeTestVocab(t)
	tok, err := NewWordPieceTokenizer(vocabPath, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.VocabSize() != 16 {
		t.Errorf("expected vocab size 16, got %d", tok.VocabSize())
	}
}

func TestEncode_BasicPadding(t *testing.T) {
	vocabPath := writeTestVocab(t)
	tok, _ := NewWordPieceTokenizer(vocabPath, 8)

	ids, mask := tok.Encode("hello world")
	if len(ids) != 8 {
		t.Fatalf("expected 8 ids, got %d", len(ids))
	}
	if len(mask) != 8 {
		t.Fatalf("expected 8 mask, got %d", len(mask))
	}

	// [CLS]=2, hello=5, world=6, [SEP]=3, [PAD]=0, [PAD]=0, [PAD]=0, [PAD]=0
	if ids[0] != 2 {
		t.Errorf("expected [CLS] (2) at position 0, got %d", ids[0])
	}
	if ids[1] != 5 {
		t.Errorf("expected 'hello' (5) at position 1, got %d", ids[1])
	}
	if ids[2] != 6 {
		t.Errorf("expected 'world' (6) at position 2, got %d", ids[2])
	}
	if ids[3] != 3 {
		t.Errorf("expected [SEP] (3) at position 3, got %d", ids[3])
	}

	// Attention mask: 1 for real tokens, 0 for padding
	if mask[0] != 1 || mask[1] != 1 || mask[2] != 1 || mask[3] != 1 {
		t.Error("expected attention mask 1 for real tokens")
	}
	if mask[4] != 0 || mask[5] != 0 {
		t.Error("expected attention mask 0 for padding")
	}
}

func TestEncode_Truncation(t *testing.T) {
	vocabPath := writeTestVocab(t)
	tok, _ := NewWordPieceTokenizer(vocabPath, 4) // maxLen=4 means room for [CLS] + 2 tokens + [SEP]

	ids, _ := tok.Encode("hello world the patient test")
	if len(ids) != 4 {
		t.Fatalf("expected 4 ids (truncated), got %d", len(ids))
	}
	if ids[0] != 2 { // [CLS]
		t.Errorf("expected [CLS] at position 0")
	}
	if ids[3] != 3 { // [SEP]
		t.Errorf("expected [SEP] at last position, got %d", ids[3])
	}
}

func TestEncode_UnknownTokens(t *testing.T) {
	vocabPath := writeTestVocab(t)
	tok, _ := NewWordPieceTokenizer(vocabPath, 8)

	ids, _ := tok.Encode("supercalifragilistic")
	// Should contain [CLS], [UNK], [SEP], then padding
	if ids[0] != 2 {
		t.Errorf("expected [CLS]")
	}
	if ids[1] != 1 { // [UNK]
		t.Errorf("expected [UNK] for unknown word, got %d", ids[1])
	}
}

func TestSplitOnPunctuation(t *testing.T) {
	result := splitOnPunctuation("hello, world.")
	expected := []string{"hello", ",", "world", "."}
	if len(result) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(result), result)
	}
	for i, tok := range result {
		if tok != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], tok)
		}
	}
}

func TestEmptyVocab(t *testing.T) {
	dir := t.TempDir()
	vocabPath := filepath.Join(dir, "empty.txt")
	os.WriteFile(vocabPath, []byte(""), 0644)

	_, err := NewWordPieceTokenizer(vocabPath, 8)
	if err == nil {
		t.Error("expected error for empty vocab")
	}
}
