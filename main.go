package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"logs-drain/drain"
)

type NormalizeRequest struct {
	Service            string  `json:"service"`
	Project            string  `json:"project"`
	StreamFilter       string  `json:"stream_filter"`       // optional: overrides service+project
	StartTime          string  `json:"start_time"`          // optional, default is yesterday
	EndTime            string  `json:"end_time"`            // optional
	Limit              int     `json:"limit"`               // optional
	VictoriaLogsURL    string  `json:"victorialogs_url"`    // optional
	Username           string  `json:"username"`            // optional
	Password           string  `json:"password"`            // optional
	InsecureSkipVerify bool    `json:"insecure_skip_verify"` // optional
	LogType            string  `json:"log_type"`            // "java" or "nginx"
	OutputFormat       string  `json:"output_format"`       // "json" (default) or "html"
	SimThreshold       float64 `json:"sim_threshold"`       // optional, default 0.75
	Depth              int     `json:"depth"`               // optional, default 5
}

type Template struct {
	ID       string `json:"id"`
	Template string `json:"template"`
	Count    int    `json:"count"`
	Level    string `json:"level,omitempty"`
	Class    string `json:"class,omitempty"`
}

type NormalizeResponse struct {
	TotalProcessed int        `json:"total_processed"`
	Skipped        int        `json:"skipped"`
	RawLines       int        `json:"raw_lines"`
	NoMsg          int        `json:"no_msg"`
	ParseErrors    int        `json:"parse_errors"`
	AccessTotal    int        `json:"access_total"`
	ErrorTotal     int        `json:"error_total"`
	Templates      []Template `json:"templates"`
}

func main() {
	fileFlag := flag.String("file", "", "Path to local JSON log file for debugging")
	logTypeFlag := flag.String("type", "nginx", "Log type (java, nginx)")
	simThresholdFlag := flag.Float64("sim", 0.75, "Similarity threshold")
	outFlag := flag.String("out", "", "Output file path (.html or .txt)")
	port := flag.String("port", "8080", "Port to run the API on")
	flag.Parse()

	if *fileFlag != "" {
		runLocalDebug(*fileFlag, *logTypeFlag, *simThresholdFlag, *outFlag)
		return
	}

	http.HandleFunc("/api/v1/normalize", normalizeHandler)

	addr := ":" + *port
	log.Printf("Starting API server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func normalizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req NormalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Setup Time Range / Default to yesterday if empty
	startTime := req.StartTime
	endTime := req.EndTime
	if startTime == "" {
		// Use UTC to align with VictoriaLogs standard storage
		yesterday := time.Now().UTC().AddDate(0, 0, -1)
		// Correct way to output a fixed time for a date in Go
		startTime = yesterday.Format("2006-01-02") + "T00:00:00Z"
		if endTime == "" {
			endTime = yesterday.Format("2006-01-02") + "T23:59:59Z"
		}
	}

	// 2. Query Construction (LogsQL)
	var queryParts []string
	
	// Revering to field filters project:"value" since {project="value"} only works for Stream Labels.
	// Users reported 0 results with {} likely because project/service are stored as fields.
	if req.Project != "" {
		queryParts = append(queryParts, fmt.Sprintf(`project:%q`, req.Project))
	}
	if req.Service != "" {
		queryParts = append(queryParts, fmt.Sprintf(`service:%q`, req.Service))
	}
	if req.StreamFilter != "" {
		queryParts = append(queryParts, req.StreamFilter)
	}

	// Time range with quotes and space after colon for standard compliance
	if startTime != "" && endTime != "" {
		queryParts = append(queryParts, fmt.Sprintf("_time: [%q, %q]", startTime, endTime))
	} else if startTime != "" {
		queryParts = append(queryParts, fmt.Sprintf("_time: >=%q", startTime))
	}

	query := strings.Join(queryParts, " ")
	if query == "" {
		query = "*"
	}

	// Select Select API URL
	vlURL := req.VictoriaLogsURL
	if vlURL == "" {
		vlURL = "http://localhost:9428"
	}
	vlURL = strings.TrimRight(vlURL, "/") + "/select/logsql/query"

	params := url.Values{}
	params.Set("query", query)
	// Keep high limit to avoid truncation
	limit := req.Limit
	if limit <= 0 {
		limit = 1000000 
	}
	params.Set("limit", fmt.Sprintf("%d", limit))

	log.Printf("Final LogsQL Query: %s", query)

	vlReq, err := http.NewRequest(http.MethodPost, vlURL, bytes.NewBufferString(params.Encode()))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vlReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if req.Username != "" {
		vlReq.SetBasicAuth(req.Username, req.Password)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: req.InsecureSkipVerify},
	}
	client := &http.Client{Timeout: 10 * time.Minute, Transport: transport}
	vlResp, err := client.Do(vlReq)
	if err != nil {
		http.Error(w, "Failed to connect to VictoriaLogs: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer vlResp.Body.Close()

	if vlResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(vlResp.Body)
		http.Error(w, fmt.Sprintf("VictoriaLogs Error: %d - %s", vlResp.StatusCode, body), http.StatusBadGateway)
		return
	}

	// 3. Process Logs
	depth := req.Depth
	if depth <= 0 {
		depth = 5
	}
	sim := req.SimThreshold
	if sim <= 0 {
		sim = 0.75
	}

	processResult := processFullLogs(vlResp.Body, req.LogType, depth, sim)

	// 4. Output
	if req.OutputFormat == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		generateHTMLReport(w, "VictoriaLogs ("+req.Project+"/"+req.Service+")", req.LogType,
			processResult.RawLines, processResult.AccessTotal, processResult.ErrorTotal,
			processResult.ParseErrors, processResult.NoMsg,
			processResult.Routes, processResult.Groups, processResult.GroupMeta)
	} else {
		w.Header().Set("Content-Type", "application/json")
		templates := make([]Template, 0, len(processResult.Groups))
		for _, g := range processResult.Groups {
			t := Template{
				ID:       g.ID,
				Template: strings.Join(g.LogEvents, " "),
				Count:    g.Count,
			}
			if meta, ok := processResult.GroupMeta[g.ID]; ok {
				t.Level = meta[0]
				t.Class = meta[1]
			}
			templates = append(templates, t)
		}
		json.NewEncoder(w).Encode(NormalizeResponse{
			TotalProcessed: processResult.TotalProcessed,
			Skipped:        processResult.Skipped,
			RawLines:       processResult.RawLines,
			NoMsg:          processResult.NoMsg,
			ParseErrors:    processResult.ParseErrors,
			AccessTotal:    processResult.AccessTotal,
			ErrorTotal:     processResult.ErrorTotal,
			Templates:      templates,
		})
	}
}

type LogProcessResult struct {
	RawLines       int
	TotalProcessed int
	Skipped        int
	NoMsg          int
	ParseErrors    int
	AccessTotal    int
	ErrorTotal     int
	Routes         []RouteItem
	Groups         []*drain.LogGroup
	GroupMeta      map[string][2]string
}

func processFullLogs(reader io.Reader, logType string, depth int, sim float64) LogProcessResult {
	if logType == "" {
		logType = "java"
	}

	d := drain.NewDrain(depth, sim, 100)
	groupMeta := make(map[string][2]string)
	routeCounts := make(map[string]int)

	nginxErrorRe := regexp.MustCompile(`^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\s+\[(\w+)\]\s+\d+#\d+:\s+(?:\*\d+\s+)?`)
	javaHeaderRe := regexp.MustCompile(`^(?:\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?\s+){1,2}(?:\[.*?\]\s+)*([A-Z]{3,8})\s+([\w\.\$]+)`)
	stackFrameRe := regexp.MustCompile(`^\s*at\s+[\w\.\$]+\(`)
	causedByRe := regexp.MustCompile(`^\s*(Caused by:|\.\.\. \d+ more)`)
	inlineStackRe := regexp.MustCompile(`\s+at\s+[\w\.\$]+\(`)
	routeRe := regexp.MustCompile(`"(?:\s*)(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+/([^/\s?]+)`)

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 5*1024*1024) // 5MB limit for extremely long lines

	res := LogProcessResult{
		GroupMeta: groupMeta,
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		res.RawLines++

		var logEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			res.ParseErrors++
			continue
		}

		msgVal, ok := logEntry["_msg"]
		if !ok {
			res.NoMsg++
			continue
		}
		msgStr, ok := msgVal.(string)
		if !ok {
			continue
		}

		// JSON de-nesting
		if len(msgStr) > 0 && msgStr[0] == '{' {
			var inner map[string]interface{}
			if err := json.Unmarshal([]byte(msgStr), &inner); err == nil {
				for _, k := range []string{"_msg", "message", "log", "content"} {
					if v, ok := inner[k].(string); ok {
						msgStr = v
						break
					}
				}
			}
		}

		var level, class string
		if logType == "nginx" {
			if m := nginxErrorRe.FindStringSubmatchIndex(msgStr); m != nil {
				if m[2] >= 0 {
					level = msgStr[m[2]:m[3]]
				}
				msgStr = strings.TrimSpace(msgStr[m[1]:])
				res.ErrorTotal++
				g := d.ProcessLine(msgStr)
				if g != nil {
					if _, seen := groupMeta[g.ID]; !seen && level != "" {
						groupMeta[g.ID] = [2]string{level, class}
					}
				}
				res.TotalProcessed++
			} else {
				res.AccessTotal++
				if m := routeRe.FindStringSubmatch(msgStr); len(m) > 1 {
					routeCounts[m[1]]++
				} else {
					routeCounts["unknown"]++
				}
				res.TotalProcessed++
			}
		} else {
			// Java logic
			if stackFrameRe.MatchString(msgStr) || causedByRe.MatchString(msgStr) {
				res.Skipped++
				continue
			}
			if m := javaHeaderRe.FindStringSubmatchIndex(msgStr); m != nil {
				if m[2] >= 0 {
					level = msgStr[m[2]:m[3]]
				}
				if m[4] >= 0 {
					class = msgStr[m[4]:m[5]]
				}
				rest := msgStr[m[1]:]
				if idx := strings.Index(rest, " - "); idx >= 0 {
					msgStr = strings.TrimSpace(rest[idx+3:])
				} else {
					msgStr = strings.TrimSpace(rest)
				}
			}
			if loc := inlineStackRe.FindStringIndex(msgStr); loc != nil {
				msgStr = strings.TrimSpace(msgStr[:loc[0]])
			}
			if msgStr == "" {
				res.Skipped++
				continue
			}
			if level == "ERROR" || level == "WARN" || level == "FATAL" {
				res.ErrorTotal++
			}
			g := d.ProcessLine(msgStr)
			if g != nil {
				if _, seen := groupMeta[g.ID]; !seen && level != "" {
					groupMeta[g.ID] = [2]string{level, class}
				}
			}
			res.TotalProcessed++
		}
	}

	// Finalize results
	var routes []RouteItem
	for k, v := range routeCounts {
		routes = append(routes, RouteItem{k, v})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Value > routes[j].Value })
	res.Routes = routes

	groups := d.GetGroups()
	sort.Slice(groups, func(i, j int) bool { return groups[i].Count > groups[j].Count })
	res.Groups = groups

	return res
}

func runLocalDebug(filePath, logType string, sim float64, outFile string) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	res := processFullLogs(f, logType, 5, sim)

	if outFile != "" && strings.HasSuffix(strings.ToLower(outFile), ".html") {
		outF, _ := os.Create(outFile)
		defer outF.Close()
		generateHTMLReport(outF, filePath, logType, res.RawLines, res.AccessTotal, res.ErrorTotal, res.ParseErrors, res.NoMsg, res.Routes, res.Groups, res.GroupMeta)
		log.Printf("Report generated: %s", outFile)
		return
	}

	// Fallback to text summary in console
	fmt.Printf("Analyzed %d lines, found %d error groups.\n", res.RawLines, len(res.Groups))
	for i, g := range res.Groups {
		if i >= 5 {
			break
		}
		fmt.Printf("[%d] Count: %d | %s\n", i+1, g.Count, strings.Join(g.LogEvents, " "))
	}
}

