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
	ErrorsOnly         bool    `json:"errors_only"`         // Only fetch error logs
	EnableLLM          bool    `json:"enable_llm"`          // Enable LLM analysis
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
	LLMAnalysis    string     `json:"llm_analysis,omitempty"`
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

	if req.ErrorsOnly {
		// 针对海量日志环境的极致性能过滤器 (符合 Google 规范且自带详细中文注释)
		// 1. 若 VictoriaLogs 已经将状态码或级别解析为结构化字段，优先匹配 (status >= 400 或 level 为 error/warn/failed 等)
		// 2. 针对 Nginx Access 未解析日志：通过 _msg 字段显式 OR 匹配常见的 HTTP 4xx 和 5xx 异常状态码 (如 " 404 ", " 500 " 等)
		// 3. 针对 Java/业务日志/未结构化 Nginx 错误日志：通过 _msg 字段匹配常见异常及报错关键字 (如 "ERROR", "Exception", "failed", "timeout" 等)
		// 4. 解决 Token 精确匹配问题：因为 VictoriaLogs 分词精确匹配且区分大小写，增加 "failed" 的多大小写变体以捕获 "No such file or directory" 类错误
		queryParts = append(queryParts, `(status:>=400 OR level:ERROR OR level:WARN OR level:err OR level:warn OR level:error OR level:fail OR level:failed OR _msg:" 400 " OR _msg:" 401 " OR _msg:" 403 " OR _msg:" 404 " OR _msg:" 405 " OR _msg:" 499 " OR _msg:" 500 " OR _msg:" 502 " OR _msg:" 503 " OR _msg:" 504 " OR _msg:" ERROR " OR _msg:" WARN " OR _msg:"Exception" OR _msg:"error" OR _msg:"ERROR" OR _msg:"Error" OR _msg:"fail" OR _msg:"failed" OR _msg:"failed" OR _msg:"failed" OR _msg:"timeout")`)
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
	llmAnalysis := ""
	if req.EnableLLM {
		llmAnalysis = getLLMAnalysis(req.LogType, processResult.Groups, processResult.GroupMeta)
	}

	if req.OutputFormat == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		generateHTMLReport(w, "VictoriaLogs ("+req.Project+"/"+req.Service+")", req.LogType, startTime, endTime,
			processResult.RawLines, processResult.AccessTotal, processResult.ErrorTotal,
			processResult.ParseErrors, processResult.NoMsg,
			processResult.Routes, processResult.Groups, processResult.GroupMeta, llmAnalysis)
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
			LLMAnalysis:    llmAnalysis,
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
			// 1. 尝试从结构化 JSON 中提取 HTTP 状态码以及内置 Level 辅助判定
			var statusVal int
			if s, ok := logEntry["status"]; ok {
				switch v := s.(type) {
				case float64:
					statusVal = int(v)
				case int:
					statusVal = v
				case string:
					fmt.Sscanf(v, "%d", &statusVal)
				}
			}
			var parsedLevel string
			if l, ok := logEntry["level"]; ok {
				if ls, ok := l.(string); ok {
					parsedLevel = strings.ToLower(ls)
				}
			}

			isNginxError := false
			m := nginxErrorRe.FindStringSubmatchIndex(msgStr)
			if m != nil {
				// 匹配标准 Nginx Error 日志 (如 [error] / [info])
				isNginxError = true
				if m[2] >= 0 {
					level = msgStr[m[2]:m[3]]
				}
				msgStr = strings.TrimSpace(msgStr[m[1]:])
			} else if statusVal >= 400 || parsedLevel == "error" || parsedLevel == "warn" || parsedLevel == "failed" || parsedLevel == "fail" || parsedLevel == "err" {
				// 匹配 HTTP 4xx/5xx 错误访问日志或显式带有错误等级的日志，将其归入异常聚类
				isNginxError = true
				level = "error"
				if parsedLevel != "" {
					level = parsedLevel
				}
			}

			if isNginxError {
				res.ErrorTotal++
				g := d.ProcessLine(msgStr)
				if g != nil {
					if _, seen := groupMeta[g.ID]; !seen && level != "" {
						groupMeta[g.ID] = [2]string{level, class}
					}
				}
				res.TotalProcessed++
			} else {
				// 仅有状态码 < 400 且无异常等级的日志才视作纯常规访问日志 (不送入聚类)
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
		generateHTMLReport(outF, filePath, logType, "", "", res.RawLines, res.AccessTotal, res.ErrorTotal, res.ParseErrors, res.NoMsg, res.Routes, res.Groups, res.GroupMeta, "")
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

func getLLMAnalysis(logType string, groups []*drain.LogGroup, groupMeta map[string][2]string) string {
	const (
		baseURL = "http://10.250.186.247:20201"
		appKey  = "9FZT8-SC002-PV6P1-UTK2Z-0106"
		secret  = "multibot@@zhiwei"
	)

	// 1. Get Token
	tokenResp, err := http.Get(fmt.Sprintf("%s/ds/api/v1/external/appKey/getToken?appkey=%s&secret=%s", baseURL, appKey, secret))
	if err != nil {
		return "LLM Error: Failed to connect to token service."
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		Success bool   `json:"success"`
		Data    string `json:"data"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil || !tokenData.Success {
		return "LLM Error: Failed to parse token."
	}
	token := tokenData.Data

	// 2. Prepare Prompt
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("你是一位资深的运维专家，请分析以下 %s 日志的异常模式并给出简洁的排查建议（总字数控制在200字以内，不要输出废话）：\n\n", logType))

	// Send top 10 groups (prioritizing errors)
	count := 0
	for _, g := range groups {
		if count >= 10 {
			break
		}
		level := ""
		if meta, ok := groupMeta[g.ID]; ok {
			level = meta[0]
		}
		// If nginx and access log (level empty), we might want to skip unless it's unusual
		// But for java, we usually care about all clusters
		sb.WriteString(fmt.Sprintf("- [%s] 频次:%d 模式: %s\n", level, g.Count, strings.Join(g.LogEvents, " ")))
		count++
	}

	// 3. Chat Request (SSE parsing)
	chatURL := baseURL + "/ds/api/v1/external/bot/api/chatPreview"
	payload := map[string]interface{}{
		"uuid": "2780eb6218c34915bc8b8ec4535a716b",
		"query": []map[string]string{
			{"role": "user", "content": sb.String()},
		},
		"clientId":  "2as9fsas9f-9edb-45b9-ab70-38028a36fdfe",
		"dialogId":  "ks9d3565-9d05-4c4c-93f6-99ebec96339f",
		"channelId": "DS",
	}
	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", chatURL, bytes.NewBuffer(payloadBytes))
	req.Header.Set("Authorization", token)
	req.Header.Set("user_id", "dwliubo")
	req.Header.Set("tenant_id", "zyxx")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "LLM Error: Request failed."
	}
	defer resp.Body.Close()

	// Parse SSE response
	var fullText strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			content := strings.TrimSpace(line[5:])
			if content == "[DONE]" {
				break
			}
			var dataObj struct {
				Content string `json:"content"`
			}
			if err := json.Unmarshal([]byte(content), &dataObj); err == nil {
				fullText.WriteString(dataObj.Content)
			}
		}
	}

	result := fullText.String()
	if result == "" {
		return "LLM Error: No response content."
	}
	return result
}
