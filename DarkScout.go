package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// Global logger
var (
	logFile    *os.File
	logger     *log.Logger
	logEnabled = true
)

func printBanner() {
	fmt.Println(`
	██████╗  █████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
	██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
	██║  ██║███████║██████╔╝█████╔╝ ███████╗██║     ██║   ██║██║   ██║   ██║   
	██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║██║     ██║   ██║██║   ██║   ██║   
	██████╔╝██║  ██║██║  ██║██║  ██╗███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
	╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

	              DarkScout - Tor Network Scraper & Recon Tool
	                    Navigate the dark web safely
	`)
}

// initLogger - Log sistemini başlatır
func initLogger() error {
	logFilename := "darkscout.log"

	// Log dosyası aç
	var err error
	logFile, err = os.OpenFile(logFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("log dosyası oluşturulamadı: %w", err)
	}

	// Sadece dosyaya yaz (konsola ayrı yazacağız)
	logger = log.New(logFile, "", log.LstdFlags)

	logger.Println("========================================")
	logger.Printf("=== Yeni Oturum Başlatıldı: %s ===", time.Now().Format("2006-01-02 15:04:05"))
	logger.Println("========================================")

	return nil
}

// logInfo - Bilgi logu
func logInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if logger != nil {
		logger.Printf("[INFO] %s", msg)
	}
}

// logError - Hata logu
func logError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if logger != nil {
		logger.Printf("[ERROR] %s", msg)
	}
}

// logSuccess - Başarı logu
func logSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if logger != nil {
		logger.Printf("[SUCCESS] %s", msg)
	}
}

// logWarning - Uyarı logu
func logWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if logger != nil {
		logger.Printf("[WARNING] %s", msg)
	}
}

// logDebug - Debug logu
func logDebug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if logger != nil {
		logger.Printf("[DEBUG] %s", msg)
	}
}

// TargetConfig - targets.yaml yapısı
type TargetConfig struct {
	Targets []struct {
		URL         string `yaml:"url"`
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"targets"`
}

// loadTargetsFromYAML - targets.yaml dosyasından hedefleri yükler
func loadTargetsFromYAML(filename string) ([]string, error) {
	logInfo("targets.yaml dosyası okunuyor: %s", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		logError("Dosya okunamadı: %v", err)
		return nil, fmt.Errorf("dosya okunamadı: %w", err)
	}

	var config TargetConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		logError("YAML parse hatası: %v", err)
		return nil, fmt.Errorf("YAML parse hatası: %w", err)
	}

	if len(config.Targets) == 0 {
		logError("targets.yaml dosyasında hedef bulunamadı")
		return nil, fmt.Errorf("targets.yaml dosyasında hedef bulunamadı")
	}

	urls := make([]string, 0, len(config.Targets))
	logger.Println("=== Yüklenen Hedefler ===")

	for i, target := range config.Targets {
		urls = append(urls, target.URL)
		msg := fmt.Sprintf("[%d] %s", i+1, target.URL)
		logger.Println(msg)

		if target.Name != "" {
			msg = fmt.Sprintf("    İsim: %s", target.Name)
			logger.Println(msg)
		}
	}

	logSuccess("Toplam %d hedef yüklendi", len(urls))
	return urls, nil
}

// createSampleTargetsFile - Örnek targets.yaml dosyası oluşturur
func createSampleTargetsFile(filename string) error {
	logInfo("Örnek targets.yaml dosyası oluşturuluyor")

	sampleContent := `# DarkScout Targets Configuration
# Her hedef için URL, isim ve açıklama belirtebilirsiniz

targets:
  - url: "http://torbuy4iw7eghmdkpllz2tjvphtsey6a47mn2mjsmcii4vlv3wr2csqd.onion/forum/"
    name: "TorBuy/TorForum"
    description: "TorBuy/TorForum"

  - url: "http://aniozgjggq2pzxznogrlpoioks7iu3emj6bwebz3yptl4pkoukzd6kid.onion/"
    name: "Ghosthub Forum"
    description: "Ghosthub Forum"

  #- url: "http://germania7zs27fu3gi76wlr5rd64cc2yjexyzvrbm4jufk7pibrpizad.onion/"
  #  name: "Germania Forum"
  #  description: "Germania Forum"

  #- url: "http://cebulka7uxchnbpvmqapg5pfos4ngaxglsktzvha7a5rigndghvadeyd.onion/"
  #  name: "Cebulka Polish"
  #  description: "Cebulka Polish"

  - url: "http://darkobds5j7xpsncsexzwhzaotyc4sshuiby3wtxslq5jy2mhrulnzad.onion/darkzone-forum/"
    name: "DarkZone Forum"
    description: "Başka bir test sitesi"

  #- url: "http://frenchpoolhdakynrvuhndrdlh5lxqp5prvh457mv26ebcdnbgqyhgyd.onion/viewforum.php?id=1"
  #  name: "DarkZone Forum"
  #  description: "Başka bir test sitesi"

  - url: "http://darknet77vonbqeatfsnawm5jtnoci5z22mxay6cizmoucgmz52mwyad.onion/"
    name: "DarkNetArmy"
    description: "Başka bir test sitesi"

  - url: "http://w4ljqtyjnxinknz4hszn4bsof7zhfy5z2h4srfss4vvkoikiwz36o3id.onion/"
    name: "Shadow Forum"
    description: "Başka bir test sitesi"

  - url: "http://pjynx7h2fag2nkg7yqj2rtboovryn7azeovvw7fxruuaeabiewar5wid.onion/"
    name: "Oberbaum"
    description: "Başka bir test sitesi"

  - url: "http://rutorbesth5lhmj47qz4fi5i4x5zvh4fizruog6iw2l3q223jmnawvid.onion/"
    name: "ruTOR"
    description: "Başka bir test sitesi"

  - url: "http://b45aqyhwqsnnr7ljygvdwhlsmzhxsevaab2au6hvroasyhxbxw6q4ayd.onion/"
    name: "Мир криминала"
    description: "Başka bir test sitesi"

  - url: "https://ezdhgsy2aw7zg54z6dqsutrduhl22moami5zv2zt6urr6vub7gs6wfad.onion/"
    name: "DEFCON"
    description: "Başka bir test sitesi"

  - url: "http://b7ehf7dabxevdsm5szkn2jecnliwzoxlsn4lijxqxikrlykbbsfrqfad.onion/"
    name: "DeepWeb Question and Answers"
    description: "Başka bir test sitesi"

  - url: "https://reycdxyc24gf7jrnwutzdn3smmweizedy7uojsa7ols6sflwu25ijoyd.onion/archives/"
    name: "Out3r Space"
    description: "Başka bir test sitesi"

  - url: "http://forums56xf3ix34sooaio4x5n275h4i7ktliy4yphhxohuemjpqovrad.onion/forums/general-discussion.9/"
    name: "DarkWeb Forums"
    description: "Başka bir test sitesi"

  - url: "http://suprbaydvdcaynfo4dgdzgxb4zuso7rftlil5yg5kqjefnw4wq4ulcad.onion/"
    name: "Suprbay"
    description: "Başka bir test sitesi"

  #- url: "http://jkie5viyrmymttownlksylz5vipyxxvs6qgy2yybgbssoiuf7a7klpqd.onion/viewforum.php?id=1"
  #  name: "FrenchPool"
  #  description: "Başka bir test sitesi"
`
	err := os.WriteFile(filename, []byte(sampleContent), 0644)
	if err != nil {
		logError("Örnek dosya oluşturulamadı: %v", err)
		return err
	}

	logSuccess("Örnek dosya oluşturuldu: %s", filename)
	return nil
}

// createTorClient - IP sızıntısını önleyen güvenli Tor HTTP client oluşturur
func createTorClient(proxyAddr string) (*http.Client, error) {
	logInfo("Tor HTTP client oluşturuluyor...")
	logDebug("Proxy adresi: %s", proxyAddr)

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		logError("SOCKS5 dialer hatası: %v", err)
		return nil, fmt.Errorf("SOCKS5 dialer hatası: %w", err)
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableKeepAlives:  false,
		DisableCompression: false,
		Proxy:              nil,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("çok fazla redirect")
			}
			return nil
		},
	}

	logSuccess("Tor HTTP client oluşturuldu (IP sızıntısı korumalı)")
	return client, nil
}

// checkTorConnection - Tor bağlantısını kontrol eder
func checkTorConnection(proxyAddr string) bool {
	logDebug("Tor bağlantısı kontrol ediliyor: %s", proxyAddr)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		logDebug("Bağlantı başarısız: %v", err)
		return false
	}
	conn.Close()

	logDebug("Bağlantı başarılı: %s", proxyAddr)
	return true
}

// detectTorPort - Aktif Tor portunu otomatik tespit eder
func detectTorPort() string {
	ports := []string{
		"127.0.0.1:9050",
		"127.0.0.1:9150",
	}

	logInfo("Otomatik port tespiti başlatıldı")

	for _, port := range ports {
		logDebug("Port deneniyor: %s", port)
		if checkTorConnection(port) {
			logSuccess("Aktif port bulundu: %s", port)
			return port
		}
	}

	logError("Hiçbir aktif Tor portu bulunamadı")
	return ""
}

// verifyTorIP - Tor üzerinden gerçekten bağlandığımızı doğrular
func verifyTorIP(client *http.Client) error {
	logInfo("Tor IP doğrulaması yapılıyor...")

	req, err := http.NewRequest("GET", "https://check.torproject.org/api/ip", nil)
	if err != nil {
		logError("İstek oluşturma hatası: %v", err)
		return fmt.Errorf("istek oluşturma hatası: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

	resp, err := client.Do(req)
	if err != nil {
		logError("Tor IP kontrolü başarısız: %v", err)
		return fmt.Errorf("Tor IP kontrolü başarısız: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("Yanıt okuma hatası: %v", err)
		return fmt.Errorf("yanıt okuma hatası: %w", err)
	}

	responseText := string(body)
	logDebug("Tor API yanıtı: %s", responseText)

	if strings.Contains(responseText, "\"IsTor\":true") || strings.Contains(responseText, "Congratulations") {
		ipPattern := regexp.MustCompile(`"IP":"([^"]+)"`)
		if matches := ipPattern.FindStringSubmatch(responseText); len(matches) > 1 {
			logSuccess("Tor bağlantısı doğrulandı - Exit Node IP: %s", matches[1])
			fmt.Printf("Tor Exit Node IP: %s\n", matches[1])
		} else {
			logSuccess("Tor bağlantısı doğrulandı")
		}
		return nil
	}

	logError("Tor bağlantısı doğrulanamadı! IP sızıntısı riski var")
	return fmt.Errorf("UYARI: Tor bağlantısı doğrulanamadı! IP sızıntısı olabilir")
}

// testDNSLeak - DNS sızıntısını test eder
func testDNSLeak(client *http.Client) {
	logInfo("DNS sızıntısı testi yapılıyor...")

	req, err := http.NewRequest("GET", "https://www.dnsleaktest.com", nil)
	if err != nil {
		logWarning("DNS leak testi yapılamadı: %v", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

	resp, err := client.Do(req)
	if err != nil {
		logDebug("DNS leak testi bağlantı hatası (normal olabilir)")
		return
	}
	defer resp.Body.Close()

	logSuccess("DNS istekleri Tor üzerinden gidiyor")
}

func performRecon(htmlContent string, baseURL string) map[string][]string {
	logInfo("Recon başlatılıyor: %s", baseURL)

	results := map[string][]string{
		"onion_links":       {},
		"external_links":    {},
		"emails":            {},
		"bitcoin_addresses": {},
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		logError("HTML parse hatası: %v", err)
		return results
	}

	baseURLParsed, _ := url.Parse(baseURL)

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		absoluteURL, err := url.Parse(href)
		if err != nil {
			return
		}
		if !absoluteURL.IsAbs() {
			absoluteURL = baseURLParsed.ResolveReference(absoluteURL)
		}

		fullURL := absoluteURL.String()

		if strings.Contains(fullURL, ".onion") {
			results["onion_links"] = append(results["onion_links"], fullURL)
		} else if absoluteURL.IsAbs() {
			results["external_links"] = append(results["external_links"], fullURL)
		}
	})

	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emails := emailPattern.FindAllString(htmlContent, -1)
	results["emails"] = emails

	btcPattern := regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b`)
	btcAddresses := btcPattern.FindAllString(htmlContent, -1)
	results["bitcoin_addresses"] = btcAddresses

	for key := range results {
		results[key] = uniqueStrings(results[key])
	}

	logDebug("Recon sonuçları: Onion=%d, External=%d, Email=%d, BTC=%d",
		len(results["onion_links"]),
		len(results["external_links"]),
		len(results["emails"]),
		len(results["bitcoin_addresses"]))

	return results
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	unique := []string{}
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			unique = append(unique, entry)
		}
	}
	return unique
}

func saveReconResults(results map[string][]string, filename string) error {
	logInfo("Recon sonuçları kaydediliyor: %s", filename)

	var content strings.Builder

	content.WriteString("=== DarkScout Recon Results ===\n")
	content.WriteString(fmt.Sprintf("Tarih: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	sections := []struct {
		key   string
		title string
	}{
		{"onion_links", "Onion Links (.onion)"},
		{"external_links", "External Links (clearnet)"},
		{"emails", "Email Addresses"},
		{"bitcoin_addresses", "Bitcoin Addresses"},
	}

	for _, section := range sections {
		items := results[section.key]
		content.WriteString(fmt.Sprintf("=== %s (%d) ===\n", section.title, len(items)))
		if len(items) == 0 {
			content.WriteString("  (bulunamadı)\n")
		} else {
			for _, item := range items {
				content.WriteString(fmt.Sprintf("  - %s\n", item))
			}
		}
		content.WriteString("\n")
	}

	err := os.WriteFile(filename, []byte(content.String()), 0644)
	if err != nil {
		logError("Recon kaydetme hatası: %v", err)
		return err
	}

	logSuccess("Recon kaydedildi: %s", filename)
	return nil
}

// processTarget - Tek bir hedefi işler
func processTarget(opts []chromedp.ExecAllocatorOption, targetURL string, targetIndex int, totalTargets int, recon bool, ssdec bool) error {
	separator := strings.Repeat("=", 70)
	fmt.Println("\n" + separator)
	fmt.Printf("Hedef [%d/%d]: %s\n", targetIndex, totalTargets, targetURL)
	fmt.Println(separator)

	logger.Println("\n" + separator)
	logger.Printf("Hedef [%d/%d]: %s", targetIndex, totalTargets, targetURL)
	logger.Println(separator)

	logInfo("Hedef işleniyor: %s", targetURL)

	// 3 deneme ile HTML al
	var htmlContent string
	var screenshot []byte
	var lastErr error
	maxRetries := 3
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, ctxCancel := chromedp.NewContext(allocCtx)
	defer ctxCancel()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		logInfo("Deneme %d/%d: %s", attempt, maxRetries, targetURL)

		ctx, timeoutCancel := context.WithTimeout(ctx, 45*time.Second)

		tasks := []chromedp.Action{
			chromedp.Navigate(targetURL),
			chromedp.Sleep(3 * time.Second),
			chromedp.WaitVisible("body", chromedp.ByQuery),
			chromedp.OuterHTML("html", &htmlContent, chromedp.ByQuery),
			chromedp.FullScreenshot(&screenshot, 90),
		}

		err := chromedp.Run(ctx, tasks...)

		if attempt == maxRetries {
			timeoutCancel()
			ctxCancel()
			cancel()
		}

		if err == nil {
			logSuccess("Sayfa başarıyla yüklendi (deneme %d)", attempt)
			lastErr = nil
			break
		}

		lastErr = err
		logWarning("Deneme %d başarısız: %v", attempt, err)
		fmt.Printf("Deneme %d başarısız: %v\n", attempt, err)

		if attempt < maxRetries {
			waitTime := 1 * time.Second
			logInfo("1 saniye bekleniyor...")
			time.Sleep(waitTime)
		}
	}

	// Tüm denemeler başarısız olduysa hata dön
	if lastErr != nil {
		logError("Scraping hatası (tüm denemeler başarısız): %v", lastErr)
		fmt.Printf("Tüm Denemeler Başarısız.")
		return fmt.Errorf("scraping hatası: %w", lastErr)
	}

	// Dosya adları oluştur
	timestamp := time.Now().Format("20060102_150405")
	sanitizedURL := strings.ReplaceAll(strings.ReplaceAll(targetURL, "http://", ""), "https://", "")
	sanitizedURL = strings.ReplaceAll(sanitizedURL, "/", "_")
	sanitizedURL = strings.Split(sanitizedURL, ".onion")[0]

	baseFilename := fmt.Sprintf("darkscout_output/%s_%s", sanitizedURL, timestamp)

	// HTML kaydet
	htmlFilename := baseFilename + ".html"
	logInfo("HTML kaydediliyor: %s", htmlFilename)
	if err := os.WriteFile(htmlFilename, []byte(htmlContent), 0644); err != nil {
		logError("HTML kaydetme hatası: %v", err)
		return fmt.Errorf("HTML kaydetme hatası: %w", err)
	}
	logSuccess("HTML kaydedildi: %s", htmlFilename)

	// Recon
	if recon {
		logInfo("Recon işlemi başlatılıyor...")
		results := performRecon(htmlContent, targetURL)

		reconFilename := baseFilename + "_recon.txt"
		if err := saveReconResults(results, reconFilename); err != nil {
			return fmt.Errorf("recon kaydetme hatası: %w", err)
		}

		fmt.Printf("\n--- Recon Özeti ---\n")
		fmt.Printf("Onion Links: %d\n", len(results["onion_links"]))
		fmt.Printf("External Links: %d\n", len(results["external_links"]))
		fmt.Printf("Emails: %d\n", len(results["emails"]))
		fmt.Printf("Bitcoin Addresses: %d\n", len(results["bitcoin_addresses"]))

		logger.Printf("Recon Özeti - Onion:%d External:%d Email:%d BTC:%d",
			len(results["onion_links"]),
			len(results["external_links"]),
			len(results["emails"]),
			len(results["bitcoin_addresses"]))
	}

	// Screenshot kaydet
	if ssdec && len(screenshot) > 0 {
		imageFilename := baseFilename + ".png"
		logInfo("Screenshot kaydediliyor: %s", imageFilename)
		if err := os.WriteFile(imageFilename, screenshot, 0644); err != nil {
			logError("Screenshot kaydetme hatası: %v", err)
			return fmt.Errorf("screenshot kaydetme hatası: %w", err)
		}
		logSuccess("Screenshot kaydedildi: %s", imageFilename)
	}

	return nil
}

func main() {
	urlFlag := flag.String("u", "", "Hedef .onion URL (boş bırakılırsa targets.yaml kullanılır)")
	ssdec := flag.Bool("ss", false, "Ekran görüntüsü al")
	recon := flag.Bool("recon", false, "Recon yap (onion links, bitcoin adresleri vs.)")
	proxy := flag.String("proxy", "127.0.0.1:9050", "Tor SOCKS5 proxy adresi")
	targetsFile := flag.String("targets", "targets.yaml", "Hedef listesi dosyası")
	createTargets := flag.Bool("create-targets", false, "Örnek targets.yaml dosyası oluştur")

	flag.Usage = func() {
		printBanner()
		fmt.Printf("Kullanım:\n")
		fmt.Printf("  go run DarkScout.go [parametreler]\n\n")

		fmt.Printf("Parametreler:\n")
		flag.PrintDefaults()

		fmt.Printf(`
Örnekler:
  # Tek hedef tarama
  go run DarkScout.go -u http://example.onion
  go run DarkScout.go -u http://example.onion -ss -recon
  go run DarkScout.go -u http://example.onion -ss -recon -proxy 127.0.0.1:9050
  
  # Toplu tarama (targets.yaml)
  go run DarkScout.go
  go run DarkScout.go -targets my_targets.yaml
  go run DarkScout.go -targets my_targets.yaml -recon -ss
  go run DarkScout.go -targets my_targets.yaml -recon -ss -proxy 127.0.0.1:9050
  
  # Örnek targets.yaml oluşturmak için
  go run DarkScout.go -create-targets

Not: Tor servisinin çalışıyor olması gerekir!
  Linux/Mac: brew install tor && tor
  Windows: Tor Browser veya standalone Tor

		`)
	}

	flag.Parse()

	printBanner()

	// Logger'ı başlat
	if err := initLogger(); err != nil {
		fmt.Println("HATA: Logger başlatılamadı:", err)
		os.Exit(1)
	}
	defer func() {
		if logFile != nil {
			logger.Println("========================================")
			logger.Println("=== DarkScout Log Kapatıldı ===")
			logger.Println("========================================")
			logFile.Close()
		}
	}()

	logInfo("DarkScout başlatıldı")

	// Örnek targets.yaml oluşturma
	if *createTargets {
		if err := createSampleTargetsFile(*targetsFile); err != nil {
			logError("Örnek dosya oluşturulamadı: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Örnek targets.yaml dosyası oluşturuldu: %s\n", *targetsFile)
		fmt.Println("\nDosyayı düzenleyip hedeflerinizi ekleyin, sonra tekrar çalıştırın:")
		fmt.Println("  go run DarkScout.go")
		os.Exit(0)
	}

	// URL listesi oluştur
	var targetURLs []string
	var isBulkScan bool

	if *urlFlag == "" {
		logInfo("URL belirtilmedi, targets.yaml yükleniyor")
		fmt.Println("URL belirtilmedi, targets.yaml dosyası yükleniyor...")

		if _, err := os.Stat(*targetsFile); os.IsNotExist(err) {
			logError("targets.yaml dosyası bulunamadı: %s", *targetsFile)
			fmt.Printf("\nHATA: %s dosyası bulunamadı!\n", *targetsFile)
			fmt.Println("\nÖrnek dosya oluşturmak için:")
			fmt.Println("  go run DarkScout.go -create-targets")
			os.Exit(1)
		}

		urls, err := loadTargetsFromYAML(*targetsFile)
		if err != nil {
			fmt.Println("HATA:", err)
			os.Exit(1)
		}
		targetURLs = urls
		isBulkScan = true
	} else {
		targetURLs = []string{*urlFlag}
		isBulkScan = false
		logInfo("Tek hedef modu: %s", *urlFlag)

		if !strings.Contains(*urlFlag, ".onion") {
			logWarning("URL bir .onion adresi değil: %s", *urlFlag)
			fmt.Println("Uyarı: Bu bir .onion URL'i değil!")
			os.Exit(0)
		}
	}

	// Tor bağlantı kontrolü
	finalProxy := *proxy

	logInfo("[1/4] Tor proxy kontrolü başlatılıyor")
	fmt.Printf("\n[1/4] Tor proxy kontrolü...\n")

	if *proxy != "127.0.0.1:9050" {
		fmt.Printf("Özel port deneniyor: %s... ", *proxy)
		if !checkTorConnection(*proxy) {
			fmt.Println("Bağlantı Kurulamadı")
			logError("Belirtilen Tor proxy'ye bağlanılamadı: %s", *proxy)
			os.Exit(1)
		}
		fmt.Println("Bağlantı Kuruldu")
		logSuccess("Tor bağlantısı başarılı: %s", *proxy)
	} else {
		fmt.Printf("Varsayılan port deneniyor: %s... ", *proxy)
		if checkTorConnection(*proxy) {
			fmt.Println("Bağlantı Kuruldu")
			logSuccess("Tor bağlantısı başarılı: %s", *proxy)
		} else {
			fmt.Println("Bağlantı Kurulamadı")
			logWarning("Port 9050 bağlantısı başarısız, 9150 deneniyor")
			fmt.Print("Alternatif port deneniyor: 127.0.0.1:9150... ")
			if checkTorConnection("127.0.0.1:9150") {
				fmt.Println("Bağlantı Kuruldu")
				finalProxy = "127.0.0.1:9150"
				logSuccess("Tor Browser portu tespit edildi: 9150")
			} else {
				fmt.Println("Bağlantı Kurulamadı")
				logError("Hiçbir Tor proxy bulunamadı")
				os.Exit(1)
			}
		}
	}

	// Güvenli HTTP client oluştur
	logInfo("[2/4] Güvenli HTTP client oluşturuluyor")
	fmt.Println("\n[2/4] Güvenli HTTP client oluşturuluyor...")
	torClient, err := createTorClient(finalProxy)
	if err != nil {
		fmt.Println("HATA: Tor client oluşturulamadı:", err)
		os.Exit(1)
	}

	// IP ve DNS sızıntısı kontrolü
	logInfo("[3/4] Güvenlik kontrolleri başlatılıyor")
	fmt.Println("\n[3/4] Güvenlik kontrolleri yapılıyor...")
	if err := verifyTorIP(torClient); err != nil {
		fmt.Println("HATA:", err)
		logError("Güvenlik kontrolü başarısız")
		os.Exit(1)
	}
	testDNSLeak(torClient)

	// Chrome context oluştur
	logInfo("[4/4] Browser başlatılıyor")
	fmt.Println("\n[4/4] Browser başlatılıyor...")
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"),
		chromedp.ProxyServer("socks5://"+finalProxy),
		chromedp.WindowSize(1920, 1080),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	logSuccess("Tüm kontroller tamamlandı!")
	fmt.Println("Tüm kontroller tamamlandı!")

	// Çıktı klasörü oluştur
	if err := os.MkdirAll("darkscout_output", 0755); err != nil {
		logError("Klasör oluşturma hatası: %v", err)
		fmt.Println("Klasör Oluşturma Hatası:", err)
		os.Exit(1)
	}

	// Hedefleri işle
	successCount := 0
	failCount := 0
	startTime := time.Now()

	if isBulkScan {
		logInfo("Toplu tarama başlatılıyor - %d hedef", len(targetURLs))
		fmt.Printf("\nToplu tarama başlatılıyor (%d hedef)...\n", len(targetURLs))
	}

	for i, targetURL := range targetURLs {
		err := processTarget(opts, targetURL, i+1, len(targetURLs), *recon, *ssdec)
		if err != nil {
			logError("Hedef işleme hatası: %v", err)
			fmt.Printf("Hata: %v\n", err)
			failCount++

			if isBulkScan {
				fmt.Println("Sonraki hedefe geçiliyor...")
				continue
			} else {
				os.Exit(1)
			}
		}
		successCount++
	}

	// Özet rapor
	duration := time.Since(startTime)
	separator := strings.Repeat("=", 70)

	fmt.Println(separator)
	fmt.Println("TARAMA RAPORU")
	fmt.Println(separator)
	fmt.Printf("Toplam Hedef: %d\n", len(targetURLs))
	fmt.Printf("Başarılı: %d\n", successCount)
	fmt.Printf("Başarısız: %d\n", failCount)
	fmt.Printf("Süre: %s\n", duration.Round(time.Second))
	fmt.Println(separator)
	fmt.Println("\nTüm işlemler tamamlandı!")

	logger.Println(separator)
	logger.Println("TARAMA RAPORU")
	logger.Println(separator)
	logger.Printf("Toplam Hedef: %d", len(targetURLs))
	logger.Printf("Başarılı: %d", successCount)
	logger.Printf("Başarısız: %d", failCount)
	logger.Printf("Süre: %s", duration.Round(time.Second))
	logger.Println(separator)

	logSuccess("Tüm işlemler tamamlandı!")
}
