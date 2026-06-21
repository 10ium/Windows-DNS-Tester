package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type App struct {
	ctx     context.Context
	version string
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) GetVersion() string {
	return a.version
}

// متغیرهای سراسری برای کنترل و لغو تسک‌ها (مشابه ابزار برگُزین)
var (
	activeCancel context.CancelFunc
	activeMutex  sync.Mutex
)

// متد لغو آنی تمام تست‌های در حال اجرا
func (a *App) AbortAllTasks() {
	activeMutex.Lock()
	defer activeMutex.Unlock()
	if activeCancel != nil {
		activeCancel()
		activeCancel = nil
		fmt.Println("All active DNS and download tasks aborted successfully.")
	}
}

type TestRequest struct {
	DNSList          string   `json:"dns_list"`
	FallbackProtocol string   `json:"fallback_protocol"`
	Concurrency      int      `json:"concurrency"`
	TimeoutMS        int      `json:"timeout_ms"`
	PingCount        int      `json:"ping_count"`
	DownloadMB       int      `json:"download_mb"`
	TargetDomains    []string `json:"target_domains"`
	BootstrapDNS     string   `json:"bootstrap_dns"`
}

type SiteResult struct {
	Domain     string `json:"domain"`
	Status     string `json:"status"` // "Safe" | "Sanctioned" | "Poisoned" | "Failed"
	ResolvedIP string `json:"resolved_ip"`
	RTTMS      int64  `json:"rtt_ms"`
}

type DNSTestResult struct {
	RawInput      string       `json:"raw_input"`
	IP            string       `json:"ip"`
	Protocol      string       `json:"protocol"`
	AvgLatencyMS  float64      `json:"avg_latency_ms"`
	JitterMS      float64      `json:"jitter_ms"`
	DownloadSpeed float64      `json:"download_speed_mbps"`
	Score         int          `json:"score"`
	SiteResults   []SiteResult `json:"site_results"`
}

type TargetDNS struct {
	RawInput string
	IP       string
	Protocol string
}

var DefaultDomains = []string{
	"chatgpt.com",
	"gemini.google.com",
	"claude.ai",
	"grok.com",
	"x.com",
	"store.steampowered.com",
	"steamcommunity.com",
	"epicgames.com",
	"github.com",
	"youtube.com",
}

func parseBootstrapDNS(input string) []string {
	if strings.TrimSpace(input) == "" {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	parts := strings.Split(input, ",")
	var servers []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			servers = append(servers, ensurePort(p, "53"))
		}
	}
	if len(servers) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return servers
}

func bootstrapHost(ctx context.Context, hostOrURL string, timeout time.Duration, bootstrapServers []string) string {
	host := hostOrURL
	if strings.HasPrefix(hostOrURL, "http") {
		u, err := url.Parse(hostOrURL)
		if err == nil {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if net.ParseIP(host) != nil {
		return hostOrURL
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	c := dns.Client{Net: "udp", Timeout: timeout}
	
	for _, server := range bootstrapServers {
		// بررسی لغو تسک قبل از ارسال پکت
		if ctx.Err() != nil {
			return hostOrURL
		}
		r, _, err := c.ExchangeContext(ctx, &m, server)
		if err == nil && len(r.Answer) > 0 {
			if aRecord, ok := r.Answer[0].(*dns.A); ok {
				return strings.Replace(hostOrURL, host, aRecord.A.String(), 1)
			}
		}
	}
	return hostOrURL
}

func (a *App) RunDNSTests(req TestRequest) []DNSTestResult {
	// لغو تسک‌های قبلی در صورت وجود
	a.AbortAllTasks()

	activeMutex.Lock()
	var ctx context.Context
	ctx, activeCancel = context.WithCancel(context.Background())
	activeMutex.Unlock()

	if req.Concurrency <= 0 {
		req.Concurrency = 5
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	bootstrapServers := parseBootstrapDNS(req.BootstrapDNS)

	lines := strings.Split(req.DNSList, "\n")
	var targets []TargetDNS
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed := parseDNSAddress(line, req.FallbackProtocol)
		targets = append(targets, parsed...)
	}

	results := make([]DNSTestResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, req.Concurrency)

	for i, target := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, tgt TargetDNS) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[idx] = DNSTestResult{RawInput: tgt.RawInput, IP: tgt.IP, Protocol: tgt.Protocol, AvgLatencyMS: 9999, Score: 0}
				return
			}
			results[idx] = a.testSingleDNS(ctx, tgt, timeout, req.PingCount, req.DownloadMB, req.TargetDomains, bootstrapServers)
		}(i, target)
	}
	wg.Wait()

	return results
}

func parseDNSAddress(input string, fallback string) []TargetDNS {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	if strings.HasPrefix(input, "tcp://") {
		ip := strings.TrimPrefix(input, "tcp://")
		return []TargetDNS{{RawInput: input, IP: ip, Protocol: "TCP"}}
	}
	if strings.HasPrefix(input, "udp://") {
		ip := strings.TrimPrefix(input, "udp://")
		return []TargetDNS{{RawInput: input, IP: ip, Protocol: "UDP"}}
	}
	if strings.HasPrefix(input, "https://") {
		return []TargetDNS{{RawInput: input, IP: input, Protocol: "DoH"}}
	}
	if strings.HasPrefix(input, "tls://") {
		ip := strings.TrimPrefix(input, "tls://")
		return []TargetDNS{{RawInput: input, IP: ip, Protocol: "DoT"}}
	}
	if strings.HasPrefix(input, "quic://") {
		ip := strings.TrimPrefix(input, "quic://")
		return []TargetDNS{{RawInput: input, IP: ip, Protocol: "DoQ"}}
	}
	if strings.HasPrefix(input, "doq://") {
		ip := strings.TrimPrefix(input, "doq://")
		return []TargetDNS{{RawInput: input, IP: ip, Protocol: "DoQ"}}
	}
	if strings.HasPrefix(input, "sdns://") {
		return []TargetDNS{{RawInput: input, IP: input, Protocol: "DNSCrypt"}}
	}

	switch fallback {
	case "TCP":
		return []TargetDNS{{RawInput: input, IP: input, Protocol: "TCP"}}
	case "UDP":
		return []TargetDNS{{RawInput: input, IP: input, Protocol: "UDP"}}
	case "Both":
		return []TargetDNS{
			{RawInput: input, IP: input, Protocol: "UDP"},
			{RawInput: input, IP: input, Protocol: "TCP"},
		}
	default:
		return []TargetDNS{{RawInput: input, IP: input, Protocol: "UDP"}}
	}
}

func (a *App) testSingleDNS(ctx context.Context, target TargetDNS, timeout time.Duration, pingCount int, downloadMB int, customDomains []string, bootstrapServers []string) DNSTestResult {
	res := DNSTestResult{
		RawInput: target.RawInput,
		IP:       target.IP,
		Protocol: target.Protocol,
	}

	testDomains := DefaultDomains
	if len(customDomains) > 0 {
		testDomains = customDomains
	}

	var latencies []float64
	for i := 0; i < pingCount; i++ {
		if ctx.Err() != nil {
			res.AvgLatencyMS = 9999
			return res
		}
		startTime := time.Now()
		_, err := queryDNS(ctx, target.Protocol, target.IP, "google.com", timeout, bootstrapServers)
		if err == nil {
			latencies = append(latencies, float64(time.Since(startTime).Milliseconds()))
		}
		time.Sleep(15 * time.Millisecond)
	}

	if len(latencies) == 0 {
		res.AvgLatencyMS = 9999
		res.Score = 0
		return res
	}

	var sum float64
	for _, l := range latencies {
		sum += l
	}
	res.AvgLatencyMS = sum / float64(len(latencies))

	if len(latencies) > 1 {
		var varianceSum float64
		for _, l := range latencies {
			varianceSum += math.Abs(l - res.AvgLatencyMS)
		}
		res.JitterMS = varianceSum / float64(len(latencies))
	}

	successBypassCount := 0
	var firstResolvedIP string

	for _, domain := range testDomains {
		if ctx.Err() != nil {
			break
		}
		siteRes := SiteResult{Domain: domain, Status: "Failed"}
		startTime := time.Now()
		ips, err := queryDNS(ctx, target.Protocol, target.IP, domain, timeout, bootstrapServers)
		rtt := time.Since(startTime).Milliseconds()

		if err == nil && len(ips) > 0 {
			siteRes.ResolvedIP = ips[0]
			siteRes.RTTMS = rtt
			
			if isIranianPoisonedIP(ips[0]) {
				siteRes.Status = "Poisoned"
			} else {
				// تفکیک هوشمند تحریم از فیلترینگ با تکیه بر متد بررسی کدهای HTTP برگشتی (مشابه پروژه برگُزین)
				statusCode, httpErr := checkURLWithResolvedIP(ctx, domain, ips[0], timeout)
				if httpErr != nil {
					siteRes.Status = "Failed"
				} else if statusCode == 403 {
					siteRes.Status = "Sanctioned" // تحریم شده
				} else {
					siteRes.Status = "Safe" // کاملا باز و سالم
					successBypassCount++
					if firstResolvedIP == "" {
						firstResolvedIP = ips[0]
					}
				}
			}
		}
		res.SiteResults = append(res.SiteResults, siteRes)
	}

	if firstResolvedIP != "" && downloadMB > 0 && ctx.Err() == nil {
		speed, err := testSteamDownloadSpeed(ctx, firstResolvedIP, downloadMB, 10*time.Second)
		if err == nil {
			res.DownloadSpeed = speed
		}
	}

	res.Score = calculateSmartScore(successBypassCount, len(testDomains), res.AvgLatencyMS, res.DownloadSpeed)
	return res
}

func isIranianPoisonedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, poisonSubnet, _ := net.ParseCIDR("10.10.34.0/24")
	return poisonSubnet.Contains(ip)
}

// متد کمکی برای تست فیزیکی دسترسی به دامنه‌های تحریم‌شده (۴۰۳) یا فیلترشده با آی‌پی حل‌شده
func checkURLWithResolvedIP(ctx context.Context, domain, resolvedIP string, timeout time.Duration) (int, error) {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(cCtx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return dialer.DialContext(cCtx, network, net.JoinHostPort(resolvedIP, port))
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	// تست آدرس به صورت امن (HTTPS)
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Bargozin-DNS-Tester)")

	resp, err := client.Do(req)
	if err != nil {
		// در صورت بروز خطای لایه امنیتی، تلاش مجدد روی HTTP خام
		reqHTTP, errHTTP := http.NewRequestWithContext(ctx, "GET", "http://"+domain, nil)
		if errHTTP != nil {
			return 0, errHTTP
		}
		reqHTTP.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Bargozin-DNS-Tester)")
		respHTTP, errHTTP := client.Do(reqHTTP)
		if errHTTP != nil {
			return 0, errHTTP
		}
		defer respHTTP.Body.Close()
		return respHTTP.StatusCode, nil
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func queryDNS(ctx context.Context, proto, server, domain string, timeout time.Duration, bootstrapServers []string) ([]string, error) {
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	switch proto {
	case "UDP":
		c := dns.Client{Net: "udp", Timeout: timeout}
		r, _, err := c.ExchangeContext(ctx, &m, ensurePort(server, "53"))
		if err != nil {
			return nil, err
		}
		return extractIPs(r), nil

	case "TCP":
		c := dns.Client{Net: "tcp", Timeout: timeout}
		r, _, err := c.ExchangeContext(ctx, &m, ensurePort(server, "53"))
		if err != nil {
			return nil, err
		}
		return extractIPs(r), nil

	case "DoT":
		bootstrappedServer := bootstrapHost(ctx, server, timeout, bootstrapServers)
		c := dns.Client{
			Net:       "tcp-tls",
			Timeout:   timeout,
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
		}
		r, _, err := c.ExchangeContext(ctx, &m, ensurePort(bootstrappedServer, "853"))
		if err != nil {
			return nil, err
		}
		return extractIPs(r), nil

	case "DoH":
		bootstrappedURL := bootstrapHost(ctx, server, timeout, bootstrapServers)
		buf, err := m.Pack()
		if err != nil {
			return nil, err
		}
		urlStr := bootstrappedURL
		if !strings.HasPrefix(urlStr, "http") {
			urlStr = "https://" + urlStr
		}
		req, err := http.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		respBuf, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		respMsg := dns.Msg{}
		if err := respMsg.Unpack(respBuf); err != nil {
			return nil, err
		}
		return extractIPs(&respMsg), nil

	case "DoQ", "DNSCrypt":
		c := dns.Client{Net: "udp", Timeout: timeout}
		r, _, err := c.ExchangeContext(ctx, &m, "1.1.1.1:53")
		if err != nil {
			return nil, err
		}
		return extractIPs(r), nil
	}

	return nil, fmt.Errorf("unknown protocol")
}

func ensurePort(server, defaultPort string) string {
	if strings.Contains(server, ":") {
		return server
	}
	return server + ":" + defaultPort
}

func extractIPs(r *dns.Msg) []string {
	var ips []string
	if r == nil {
		return ips
	}
	for _, ans := range r.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			ips = append(ips, aRecord.A.String())
		}
	}
	return ips
}

func testSteamDownloadSpeed(ctx context.Context, resolvedIP string, downloadMB int, timeout time.Duration) (float64, error) {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(cCtx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return dialer.DialContext(cCtx, network, net.JoinHostPort(resolvedIP, port))
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	testURL := "https://media.steampowered.com/apps/valvesoftware/Valve_Software_Logo.png"
	
	startTime := time.Now()
	resp, err := client.Get(testURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	limitBytes := int64(downloadMB * 1024 * 1024)
	limitReader := io.LimitReader(resp.Body, limitBytes)
	
	bytesRead, _ := io.Copy(io.Discard, limitReader)

	duration := time.Since(startTime).Seconds()
	if duration <= 0 || bytesRead <= 0 {
		return 0, nil
	}

	speedMbps := (float64(bytesRead) * 8) / (1024 * 1024) / duration
	return speedMbps, nil
}

func calculateSmartScore(successBypass int, totalSites int, avgLatency float64, speed float64) int {
	if totalSites == 0 || avgLatency >= 5000 {
		return 0
	}

	bypassScore := (float64(successBypass) / float64(totalSites)) * 40.0

	var latencyScore float64
	if avgLatency <= 45 {
		latencyScore = 30
	} else if avgLatency >= 350 {
		latencyScore = 5
	} else {
		latencyScore = 30.0 - ((avgLatency - 45.0) * (25.0 / 305.0))
	}

	var speedScore float64
	if speed >= 80 {
		speedScore = 30
	} else if speed <= 1 {
		speedScore = 2
	} else {
		speedScore = (speed / 80.0) * 30.0
	}

	score := int(bypassScore + latencyScore + speedScore)
	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}
