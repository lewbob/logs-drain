package drain

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// LogGroup represents a parsed template and its occurrences.
type LogGroup struct {
	ID        string   `json:"id"`
	LogEvents []string `json:"log_events"` // template representation
	Count     int      `json:"count"`
}

type Node struct {
	Children  map[string]*Node
	LogGroups []*LogGroup
}

// Drain implementation
type Drain struct {
	Depth        int
	ST           float64
	MaxChildren  int
	Root         *Node
	mu           sync.Mutex
	LogGroups    []*LogGroup
	TokenMaskers []*regexp.Regexp
}

func NewDrain(depth int, st float64, maxChildren int) *Drain {
	return &Drain{
		Depth:       depth,
		ST:          st,
		MaxChildren: maxChildren,
		Root: &Node{
			Children:  make(map[string]*Node),
			LogGroups: make([]*LogGroup, 0),
		},
		LogGroups: make([]*LogGroup, 0),
		TokenMaskers: []*regexp.Regexp{
			// Email addresses (e.g., customer@example.com)
			regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			// IP address
			regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
			// Date and Time (e.g., 2025-12-12 16:07:54.941)
			regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`),
			regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b`),
			// Hex / UUIDs / etc.
			regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
			regexp.MustCompile(`\b0x[a-fA-F0-9]+\b`),
			// Common business alphanumeric placeholders (txn_xxx, ORD-xxx, user-xxx)
			regexp.MustCompile(`(txn_|ORD-|user)[a-zA-Z0-9]+`),
			// Single-quoted string literals — promo codes, config values, etc. (e.g., 'SUMMERSALE')
			regexp.MustCompile(`'[^']{1,64}'`),
			// Any remaining numbers including decimals (e.g., 10.00, 10000ms)
			regexp.MustCompile(`\d+(?:\.\d+)?`),
		},
	}
}

func (d *Drain) Preprocess(msg string) []string {
	msg = strings.TrimSpace(msg)
	for _, numRe := range d.TokenMaskers {
		msg = numRe.ReplaceAllString(msg, "<*>")
	}
	// Also mask anything with both digits and characters?
	// Splitting by spaces
	tokens := strings.Fields(msg)
	return tokens
}

func (d *Drain) ProcessLine(msg string) *LogGroup {
	d.mu.Lock()
	defer d.mu.Unlock()

	tokens := d.Preprocess(msg)
	if len(tokens) == 0 {
		return nil
	}

	match := d.treeSearch(d.Root, tokens)
	if match == nil {
		return d.addSeqToPrefixTree(d.Root, tokens)
	}
	
	// Update template
	d.updateLogGroup(match, tokens)
	return match
}

func (d *Drain) treeSearch(rn *Node, tokens []string) *LogGroup {
	tokenLen := strconv.Itoa(len(tokens))
	child, ok := rn.Children[tokenLen]
	if !ok {
		return nil
	}
	
	cur := child
	depth := 1 // tokenLen is level 0
	
	for depth < d.Depth {
		if depth-1 >= len(tokens) {
			break
		}
		token := tokens[depth-1]
		
		nextCur, ok := cur.Children[token]
		if !ok {
			nextCur, ok = cur.Children["<*>"]
			if !ok {
				return nil
			}
		}
		cur = nextCur
		depth++
	}

	return d.fastMatch(cur.LogGroups, tokens)
}

func (d *Drain) fastMatch(groups []*LogGroup, tokens []string) *LogGroup {
	var maxSim float64 = -1
	var bestMatch *LogGroup

	for _, group := range groups {
		sim := d.getSeqDistance(group.LogEvents, tokens)
		if sim >= d.ST && sim > maxSim {
			maxSim = sim
			bestMatch = group
		}
	}
	return bestMatch
}

func (d *Drain) getSeqDistance(seq1 []string, seq2 []string) float64 {
	if len(seq1) != len(seq2) {
		return 0 // they should be placed under same token length
	}
	if len(seq1) == 0 {
		return 1.0
	}
	var match int
	for i := 0; i < len(seq1); i++ {
		if seq1[i] == seq2[i] || seq1[i] == "<*>" {
			match++
		}
	}
	return float64(match) / float64(len(seq1))
}

func (d *Drain) addSeqToPrefixTree(rn *Node, tokens []string) *LogGroup {
	tokenLen := strconv.Itoa(len(tokens))
	child, ok := rn.Children[tokenLen]
	if !ok {
		child = &Node{
			Children:  make(map[string]*Node),
			LogGroups: make([]*LogGroup, 0),
		}
		rn.Children[tokenLen] = child
	}
	
	cur := child
	depth := 1

	for depth < d.Depth {
		if depth-1 >= len(tokens) {
			break
		}
		token := tokens[depth-1]
		
		_, ok := cur.Children[token]
		if !ok {
			if len(cur.Children) >= d.MaxChildren {
				token = "<*>"
				_, hasStar := cur.Children["<*>"]
				if !hasStar {
					cur.Children["<*>"] = &Node{Children: make(map[string]*Node)}
				}
			} else {
				cur.Children[token] = &Node{Children: make(map[string]*Node)}
			}
		}
		cur = cur.Children[token]
		depth++
	}

	lg := &LogGroup{
		ID:        strconv.Itoa(len(d.LogGroups) + 1),
		LogEvents: make([]string, len(tokens)),
		Count:     1,
	}
	copy(lg.LogEvents, tokens)
	cur.LogGroups = append(cur.LogGroups, lg)
	d.LogGroups = append(d.LogGroups, lg)
	return lg
}

func (d *Drain) updateLogGroup(lg *LogGroup, tokens []string) {
	lg.Count++
	for i := 0; i < len(lg.LogEvents); i++ {
		if lg.LogEvents[i] != tokens[i] {
			lg.LogEvents[i] = "<*>" // Generalize
		}
	}
}

func (d *Drain) GetGroups() []*LogGroup {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.LogGroups
}
