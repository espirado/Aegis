package sanitizer

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"

	"github.com/espirado/aegis/pkg/phi"
)

var (
	markdownLinkRe = regexp.MustCompile(`\[([^\]]*)\]\(([^)]+)\)`)
	codeBlockRe    = regexp.MustCompile("(?s)```[a-z]*\n?(.*?)```")
	inlineCodeRe   = regexp.MustCompile("`([^`]+)`")
	base64BlockRe  = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	jsonStringRe   = regexp.MustCompile(`"[^"]*"`)
)

// scanExfiltration checks for PHI hidden in indirect channels.
func scanExfiltration(text string, patterns []phi.Pattern) []DetectedEntity {
	var entities []DetectedEntity

	entities = append(entities, scanURLParams(text, patterns)...)
	entities = append(entities, scanMarkdownLinks(text, patterns)...)
	entities = append(entities, scanCodeBlocks(text, patterns)...)
	entities = append(entities, scanBase64(text, patterns)...)

	return entities
}

// scanURLParams extracts URLs from text and checks query parameters for PHI.
func scanURLParams(text string, patterns []phi.Pattern) []DetectedEntity {
	var entities []DetectedEntity

	urlRe := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	urls := urlRe.FindAllStringIndex(text, -1)

	for _, loc := range urls {
		rawURL := text[loc[0]:loc[1]]
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		params := parsed.Query()
		for key, values := range params {
			for _, val := range values {
				combined := key + "=" + val
				for _, p := range patterns {
					if p.Regex.MatchString(combined) {
						entities = append(entities, DetectedEntity{
							Type:       string(p.Type),
							StartChar:  loc[0],
							EndChar:    loc[1],
							Confidence: 0.9,
							Channel:    "url_param",
						})
					}
				}
			}
		}
	}

	return entities
}

// scanMarkdownLinks checks markdown link text and URLs for PHI.
func scanMarkdownLinks(text string, patterns []phi.Pattern) []DetectedEntity {
	var entities []DetectedEntity

	matches := markdownLinkRe.FindAllStringSubmatchIndex(text, -1)
	for _, match := range matches {
		linkText := text[match[2]:match[3]]
		linkURL := text[match[4]:match[5]]

		for _, p := range patterns {
			if p.Regex.MatchString(linkText) || p.Regex.MatchString(linkURL) {
				entities = append(entities, DetectedEntity{
					Type:       string(p.Type),
					StartChar:  match[0],
					EndChar:    match[1],
					Confidence: 0.85,
					Channel:    "markdown",
				})
			}
		}

		// Also check URL-decoded form of the link href
		if decoded, err := url.QueryUnescape(linkURL); err == nil && decoded != linkURL {
			for _, p := range patterns {
				if p.Regex.MatchString(decoded) {
					entities = append(entities, DetectedEntity{
						Type:       string(p.Type),
						StartChar:  match[0],
						EndChar:    match[1],
						Confidence: 0.9,
						Channel:    "markdown",
					})
				}
			}
		}
	}

	return entities
}

// scanCodeBlocks checks content inside code fences for PHI.
func scanCodeBlocks(text string, patterns []phi.Pattern) []DetectedEntity {
	var entities []DetectedEntity

	for _, re := range []*regexp.Regexp{codeBlockRe, inlineCodeRe} {
		matches := re.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) < 4 {
				continue
			}
			content := text[match[2]:match[3]]
			for _, p := range patterns {
				if p.Regex.MatchString(content) {
					entities = append(entities, DetectedEntity{
						Type:       string(p.Type),
						StartChar:  match[0],
						EndChar:    match[1],
						Confidence: 0.85,
						Channel:    "code_block",
					})
				}
			}

			// Check JSON strings within code blocks for PHI
			jsonMatches := jsonStringRe.FindAllString(content, -1)
			for _, js := range jsonMatches {
				unquoted := strings.Trim(js, `"`)
				for _, p := range patterns {
					if p.Regex.MatchString(unquoted) {
						entities = append(entities, DetectedEntity{
							Type:       string(p.Type),
							StartChar:  match[0],
							EndChar:    match[1],
							Confidence: 0.85,
							Channel:    "tool_arg",
						})
					}
				}
			}
		}
	}

	return entities
}

// scanBase64 finds base64-encoded strings, decodes them, and checks for PHI.
func scanBase64(text string, patterns []phi.Pattern) []DetectedEntity {
	var entities []DetectedEntity

	matches := base64BlockRe.FindAllStringIndex(text, -1)
	for _, loc := range matches {
		encoded := text[loc[0]:loc[1]]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				continue
			}
		}

		decodedStr := string(decoded)
		// Only check if decoded content looks like text (has printable chars)
		printable := 0
		for _, r := range decodedStr {
			if r >= 32 && r < 127 {
				printable++
			}
		}
		if len(decodedStr) == 0 || float64(printable)/float64(len(decodedStr)) < 0.7 {
			continue
		}

		for _, p := range patterns {
			if p.Regex.MatchString(decodedStr) {
				entities = append(entities, DetectedEntity{
					Type:       string(p.Type),
					StartChar:  loc[0],
					EndChar:    loc[1],
					Confidence: 0.9,
					Channel:    "base64",
				})
			}
		}
	}

	return entities
}
