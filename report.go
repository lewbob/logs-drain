package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"logs-drain/drain"
)

// RouteItem holds a route segment and its count
type RouteItem struct {
	Key   string
	Value int
}

func generateHTMLReport(w io.Writer, filePath, logType string, rawLines, accessTotal, errorTotal, parseErrors, noMsg int, routes []RouteItem, groups []*drain.LogGroup, groupMeta map[string][2]string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	errorRate := float64(0)
	if rawLines > 0 {
		errorRate = float64(errorTotal) / float64(rawLines) * 100
	}

	bw := bufio.NewWriter(w)
	defer bw.Flush()

	bw.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>系统分析报告</title>
<style>
:root {
  --primary: #1677ff;
  --bg: #f4f7f9;
  --card-bg: #ffffff;
  --text: #1f2329;
  --text-secondary: #646a73;
  --border: #dee0e3;
  --error: #f54a45;
  --success: #34c724;
  --warning: #ff7d00;
  --radius: 8px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, system-ui, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
  background-color: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 40px 20px;
}

.container { max-width: 1200px; margin: 0 auto; }

/* Dashboard Header */
.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}
.title-group h1 { font-size: 24px; font-weight: 600; color: var(--text); }
.title-group p { font-size: 14px; color: var(--text-secondary); margin-top: 4px; }

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}
.stat-card {
  background: var(--card-bg);
  padding: 24px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}
.stat-label { font-size: 14px; color: var(--text-secondary); margin-bottom: 8px; }
.stat-value { font-size: 28px; font-weight: 700; color: var(--text); }
.stat-value.error { color: var(--error); }
.stat-value.primary { color: var(--primary); }

/* Main Section Card */
.section-card {
  background: var(--card-bg);
  padding: 30px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  margin-bottom: 30px;
}
.section-header {
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.section-header h2 { font-size: 18px; font-weight: 600; }

/* Data Table */
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 12px 16px; background: #f8f9fa; font-size: 14px; color: var(--text-secondary); border-bottom: 1px solid var(--border); }
td { padding: 16px; font-size: 14px; border-bottom: 1px solid var(--border); }
tr:hover { background-color: #fcfcfc; }

.route-text { font-family: ui-monospace, menlo, "Cascadia Code", monospace; color: var(--primary); font-weight: 500; }
.progress-container { width: 100%; height: 6px; background: #eff1f3; border-radius: 3px; overflow: hidden; margin-top: 8px; }
.progress-bar { height: 100%; background: var(--primary); border-radius: 3px; }

/* Patterns List */
.pattern-item {
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 16px;
  background: #fafbfc;
}
.pattern-meta { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; }
.badge { font-size: 12px; padding: 2px 8px; border-radius: 4px; font-weight: 500; }
.badge-err { background: #feebe9; color: var(--error); }
.badge-count { background: #e8f3ff; color: var(--primary); }
.code-block {
  font-family: monospace;
  font-size: 13px;
  color: var(--text-secondary);
  background: #fff;
  padding: 12px;
  border: 1px solid #eef0f2;
  border-radius: 4px;
  word-break: break-all;
}

/* Advice Grid */
.advice-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
.advice-card {
  padding: 20px;
  background: #fdfdfd;
  border: 1px solid var(--border);
  border-radius: 6px;
}
.advice-card h4 { display: flex; align-items: center; gap: 8px; font-size: 15px; margin-bottom: 8px; color: var(--text); }
.advice-card h4 i { color: var(--warning); font-style: normal; }
.advice-card p { font-size: 14px; color: var(--text-secondary); }

footer {
  text-align: center;
  padding: 40px;
  color: var(--text-secondary);
  font-size: 13px;
}

@media (max-width: 768px) {
  .advice-grid { grid-template-columns: 1fr; }
  .stats-grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>
<div class="container">
	`)

	// Header
	title := "日志智能分析报告"
	if logType == "nginx" {
		title = "Nginx 系统运行分析报告"
	} else if logType == "java" {
		title = "Java 业务排障分析报告"
	}
	fmt.Fprintf(bw, `
  <div class="dashboard-header">
    <div class="title-group">
      <h1>%s</h1>
      <p>数据源: %s | 基于 Drain 聚类模型</p>
    </div>
    <div style="text-align: right">
      <div style="font-size: 13px; color: var(--text-secondary)">分析时间</div>
      <div style="font-size: 15px; font-weight: 500">%s</div>
    </div>
  </div>
`, title, filePath, now)

	// Stats Section
	okTotal := accessTotal
	if logType == "java" {
		okTotal = rawLines - errorTotal
	}
	fmt.Fprintf(bw, `
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">分析样本总量</div>
      <div class="stat-value">%d</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">正常/常规量</div>
      <div class="stat-value primary">%d</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">异常模式发现</div>
      <div class="stat-value error">%d</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">异常占比</div>
      <div class="stat-value error">%.2f%%</div>
    </div>
  </div>
`, rawLines, okTotal, errorTotal, errorRate)

	// Route TOP 10 (Only for Nginx)
	if logType == "nginx" && len(routes) > 0 {
		bw.WriteString(`
  <div class="section-card">
    <div class="section-header">
      <h2>高频访问路径 TOP 10</h2>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width: 60px">#</th>
          <th>URL 路径</th>
          <th style="width: 120px">访问量</th>
          <th style="width: 100px; text-align: right">占比</th>
        </tr>
      </thead>
      <tbody>
`)
		totalForRoutes := accessTotal
		if totalForRoutes == 0 {
			for _, r := range routes {
				totalForRoutes += r.Value
			}
		}
		for i, r := range routes {
			if i >= 10 {
				break
			}
			pct := float64(0)
			if totalForRoutes > 0 {
				pct = float64(r.Value) / float64(totalForRoutes) * 100
			}
			fmt.Fprintf(bw, `
        <tr>
          <td style="color: var(--text-secondary)">%d</td>
          <td>
            <div class="route-text">/%s</div>
            <div class="progress-container"><div class="progress-bar" style="width: %.1f%%"></div></div>
          </td>
          <td style="font-weight: 500">%d</td>
          <td style="text-align: right; font-weight: 500">%.1f%%</td>
        </tr>
`, i+1, r.Key, pct, r.Value, pct)
		}
		bw.WriteString(`</tbody></table></div>`)
	}

	// Patterns Section
	fmt.Fprintf(bw, `
  <div class="section-card">
    <div class="section-header">
      <h2>日志模式聚合 (%d 类特征)</h2>
    </div>
    <div class="pattern-list">
`, len(groups))
	for i, g := range groups {
		level := "ERROR"
		class := ""
		if m, ok := groupMeta[g.ID]; ok {
			level = strings.ToUpper(m[0])
			class = m[1]
		}
		tpl := strings.Join(g.LogEvents, " ")
		displayLevel := level
		if class != "" {
			displayLevel = fmt.Sprintf("%s · %s", level, class)
		}
		fmt.Fprintf(bw, `
      <div class="pattern-item">
        <div class="pattern-meta">
          <span class="badge badge-err">%s</span>
          <span class="badge badge-count">特征 #%d</span>
          <span style="font-size: 13px; color: var(--text-secondary)">发生频次: %d</span>
        </div>
        <div class="code-block">%s</div>
      </div>
`, displayLevel, i+1, g.Count, tpl)
	}
	bw.WriteString(`</div></div>`)

	// Advice Section
	var adviceHTML string
	if logType == "nginx" {
		adviceHTML = `
      <div class="advice-card">
        <h4><i>⚠️</i> 上游连接及链路异常</h4>
        <p>发现大量被拒绝或超时。请检查内网防火墙配置、后端服务监听地址及 Nginx <code>proxy_pass</code> 配置正确性。</p>
      </div>
      <div class="advice-card">
        <h4><i>⚠️</i> 客户端请求超限风险</h4>
        <p>特定模式显示请求体过大被拦截。若业务包含大文件上传，请考虑增大 <code>client_max_body_size</code> 参数。</p>
      </div>
      <div class="advice-card">
        <h4><i>⚠️</i> 后端响应超时预警</h4>
        <p>监测到后端响应速度下降。建议排查慢查询或高负载接口，并根据实际情况放宽 <code>proxy_read_timeout</code> 阈值。</p>
      </div>
      <div class="advice-card">
        <h4><i>⚠️</i> 集群可用性严重警告</h4>
        <p>若出现 "No Live Upstreams" 模式，说明所有后端节点失联，请立即核对服务发现机制或物理集群状态。</p>
      </div>`
	} else {
		adviceHTML = `
      <div class="advice-card">
        <h4><i>⚠️</i> 数据库连接异常</h4>
        <p>发现 Connection Reset 或 Timeout。请检查数据库连接数配额、长连接生命周期设置及网络抖动情况。</p>
      </div>
      <div class="advice-card">
        <h4><i>⚠️</i> 业务并发处理瓶颈</h4>
        <p>监测到 Thread Pool 满载或拒绝策略触发。建议优化代码同步锁逻辑，或通过参数调整增大业务线程池深度。</p>
      </div>
      <div class="advice-card">
        <h4><i>⚠️</i> 外部 API 调用失败</h4>
        <p>存在下游接口调用超时。请核对对端可用性 SLA，并考虑在核心链路增加熔断降级（Hystrix/Sentinel）保护。</p>
      </div>
      <div class="advice-card">
        <h4><i>⚠️</i> 资源泄露/溢出风险</h4>
        <p>若出现 OutOfMemory 或频繁 FullGC 模式，请导出 Heap Dump 进行内存泄漏分析，并核对 JVM 内存分配比例。</p>
      </div>`
	}

	bw.WriteString(`
  <div class="section-card">
    <div class="section-header">
      <h2>智能排障优化建议</h2>
    </div>
    <div class="advice-grid">`)
	bw.WriteString(adviceHTML)
	bw.WriteString(`
    </div>
  </div>
`)

	fmt.Fprintf(bw, `
    <footer>
      <p>Log Intelligence Analysis System &middot; 梧桐大数据开放平台</p>
      <p style="margin-top: 8px; opacity: 0.6">基于 Drain 聚类模型自动生成 | %s</p>
    </footer>
  </div>
</body>
</html>`, now)
}
