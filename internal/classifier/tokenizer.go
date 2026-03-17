package classifier

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// WordPieceTokenizer implements the WordPiece tokenization used by
// DistilBERT/BERT models. Pure Go, no CGo dependencies.
type WordPieceTokenizer struct {
	vocab   map[string]int32
	idToTok map[int32]string
	unkID   int32
	clsID   int32
	sepID   int32
	padID   int32
	maxLen  int
}

// NewWordPieceTokenizer loads a vocab.txt file and builds the tokenizer.
func NewWordPieceTokenizer(vocabPath string, maxLen int) (*WordPieceTokenizer, error) {
	f, err := os.Open(vocabPath)
	if err != nil {
		return nil, fmt.Errorf("tokenizer: open vocab: %w", err)
	}
	defer f.Close()

	vocab := make(map[string]int32)
	idToTok := make(map[int32]string)
	scanner := bufio.NewScanner(f)
	var id int32
	for scanner.Scan() {
		token := scanner.Text()
		vocab[token] = id
		idToTok[id] = token
		id++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("tokenizer: read vocab: %w", err)
	}

	if len(vocab) == 0 {
		return nil, fmt.Errorf("tokenizer: empty vocab file")
	}

	getID := func(tok string) int32 {
		if id, ok := vocab[tok]; ok {
			return id
		}
		return 0
	}

	return &WordPieceTokenizer{
		vocab:   vocab,
		idToTok: idToTok,
		unkID:   getID("[UNK]"),
		clsID:   getID("[CLS]"),
		sepID:   getID("[SEP]"),
		padID:   getID("[PAD]"),
		maxLen:  maxLen,
	}, nil
}

// Encode tokenizes text and returns input_ids and attention_mask,
// both padded/truncated to maxLen.
func (t *WordPieceTokenizer) Encode(text string) (inputIDs []int64, attentionMask []int64) {
	tokens := t.tokenize(text)

	// Truncate to maxLen - 2 to leave room for [CLS] and [SEP]
	if len(tokens) > t.maxLen-2 {
		tokens = tokens[:t.maxLen-2]
	}

	ids := make([]int64, 0, t.maxLen)
	ids = append(ids, int64(t.clsID))
	for _, tok := range tokens {
		if id, ok := t.vocab[tok]; ok {
			ids = append(ids, int64(id))
		} else {
			ids = append(ids, int64(t.unkID))
		}
	}
	ids = append(ids, int64(t.sepID))

	mask := make([]int64, len(ids))
	for i := range mask {
		mask[i] = 1
	}

	// Pad to maxLen
	for len(ids) < t.maxLen {
		ids = append(ids, int64(t.padID))
		mask = append(mask, 0)
	}

	return ids, mask
}

// tokenize applies the full BERT tokenization pipeline:
// lowercase → split on whitespace/punctuation → WordPiece
func (t *WordPieceTokenizer) tokenize(text string) []string {
	text = strings.ToLower(text)
	text = stripAccents(text)

	words := splitOnPunctuation(text)

	var tokens []string
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		subTokens := t.wordPiece(word)
		tokens = append(tokens, subTokens...)
	}

	return tokens
}

// wordPiece splits a single word into sub-word tokens.
func (t *WordPieceTokenizer) wordPiece(word string) []string {
	if _, ok := t.vocab[word]; ok {
		return []string{word}
	}

	runes := []rune(word)
	var tokens []string
	start := 0

	for start < len(runes) {
		end := len(runes)
		var bestToken string
		for start < end {
			substr := string(runes[start:end])
			if start > 0 {
				substr = "##" + substr
			}
			if _, ok := t.vocab[substr]; ok {
				bestToken = substr
				break
			}
			end--
		}
		if bestToken == "" {
			tokens = append(tokens, "[UNK]")
			break
		}
		tokens = append(tokens, bestToken)
		start = end
	}

	return tokens
}

// splitOnPunctuation splits text on whitespace and punctuation characters,
// keeping punctuation as separate tokens (BERT-style).
func splitOnPunctuation(text string) []string {
	var result []string
	var current strings.Builder

	for _, r := range text {
		if unicode.IsSpace(r) {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
		} else if unicode.IsPunct(r) || isControlOrSymbol(r) {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			result = append(result, string(r))
		} else {
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

func isControlOrSymbol(r rune) bool {
	return unicode.Is(unicode.Mn, r) || unicode.IsControl(r) || unicode.IsSymbol(r)
}

// stripAccents removes combining diacritical marks.
func stripAccents(text string) string {
	var b strings.Builder
	for _, r := range text {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// VocabSize returns the number of tokens in the vocabulary.
func (t *WordPieceTokenizer) VocabSize() int {
	return len(t.vocab)
}
