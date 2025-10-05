package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"golang.org/x/net/proxy"
)

const (
	crlf = "\r\n"
)

func main() {
	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("🧅 Onion Courier Mixnet endpoint server for dizum m2n running 🚀\n")
	log.Fatal(http.ListenAndServe(":8088", nil))
}

func normalizeLineEndings(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte(crlf))
	return data
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		randomDelay := time.Duration(time.Now().UnixNano()%5000+1000) * time.Millisecond
		time.Sleep(randomDelay)
		fmt.Fprint(w, "OK")
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var content []byte
	var err error

	contentType := r.Header.Get("Content-Type")
	if contentType != "" && contentType != "application/octet-stream" {
		if err := r.ParseMultipartForm(10 << 20); err == nil {
			if fileHeader := r.MultipartForm.File["file"]; len(fileHeader) > 0 {
				file, err := fileHeader[0].Open()
				if err == nil {
					defer file.Close()
					content, err = ioutil.ReadAll(file)
				}
			}
		}
	}

	if content == nil {
		content, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}
	}
	defer r.Body.Close()

	if len(content) == 0 {
		return
	}

	normalized := normalizeLineEndings(content)
	forwardViaEmail(normalized)
}

func forwardViaEmail(message []byte) {
	from := "anonymous"
	to := "mail2news@dizum.com"
	host := "smtp.dizum.com"
	port := ":2525"
	proxyAddr := "127.0.0.1:9050"

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return
	}

	smtpClient, err := dialSMTP(dialer, host, port)
	if err != nil {
		return
	}
	defer smtpClient.Quit()

	if err = smtpClient.StartTLS(&tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}); err != nil {
		return
	}

	if err = smtpClient.Mail(from); err != nil {
		return
	}
	if err = smtpClient.Rcpt(to); err != nil {
		return
	}

	w, err := smtpClient.Data()
	if err != nil {
		return
	}
	_, err = w.Write(message)
	if err != nil {
		return
	}
	err = w.Close()
	if err != nil {
		return
	}
}

func dialSMTP(dialer proxy.Dialer, host, port string) (*smtp.Client, error) {
	conn, err := dialer.Dial("tcp", host+port)
	if err != nil {
		return nil, err
	}
	return smtp.NewClient(conn, host)
}
