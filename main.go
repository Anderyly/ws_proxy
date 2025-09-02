package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/aWildProgrammer/fconf"
	"github.com/gorilla/websocket"
)

var (
	UUID        = getEnv("UUID", GetConf("server.uuid"))
	uuid        = strings.ReplaceAll(UUID, "-", "")
	DOMAIN      = getEnv("DOMAIN", GetConf("main.domain"))
	NAME        = getEnv("NAME", GetConf("main.name"))
	Port        = getEnv("PORT", GetConf("server.port"))
	WsPath      = getEnv("WS_PATH", GetConf("server.ws_path"))
	CertAddress = getEnv("CERT_ADDRESS", GetConf("ssl.cert_address"))
	KeyAddress  = getEnv("KEY_ADDRESS", GetConf("ssl.key_address"))
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	// Load SSL certificate
	cert, err := tls.LoadX509KeyPair(CertAddress, KeyAddress)
	if err != nil {
		log.Fatal("Failed to load SSL certificate:", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create HTTP handlers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("Unauthorized access, please start through the game page (over HTTPS)\n"))
	})

	http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		vlessURL := fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%S#%s",
			UUID, DOMAIN, DOMAIN, DOMAIN, WsPath, NAME)

		base64Content := base64.StdEncoding.EncodeToString([]byte(vlessURL))

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte(base64Content + "\n"))
	})

	http.HandleFunc(WsPath, handleWebSocket)

	// Create HTTPS server
	server := &http.Server{
		Addr:      ":" + Port,
		TLSConfig: tlsConfig,
	}

	log.Printf("HTTPS Server is running on port %s", Port)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("WebSocket read error:", err)
			break
		}

		if len(msg) < 18 {
			continue
		}

		if err := processVLESSMessage(conn, msg); err != nil {
			log.Println("Error processing message:", err)
		}
	}
}

func processVLESSMessage(ws *websocket.Conn, msg []byte) error {
	// Parse VLESS protocol
	version := msg[0]
	id := msg[1:17]

	// Verify UUID
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return err
	}

	for i, v := range id {
		if v != uuidBytes[i] {
			return fmt.Errorf("invalid UUID")
		}
	}

	// Parse address info
	i := int(msg[17]) + 19
	if i+2 >= len(msg) {
		return fmt.Errorf("invalid message length")
	}

	targetPort := binary.BigEndian.Uint16(msg[i : i+2])
	i += 2

	if i >= len(msg) {
		return fmt.Errorf("invalid message length")
	}

	atyp := msg[i]
	i++

	var host string
	switch atyp {
	case 1: // IPv4
		if i+4 > len(msg) {
			return fmt.Errorf("invalid IPv4 address")
		}
		host = fmt.Sprintf("%d.%d.%d.%d", msg[i], msg[i+1], msg[i+2], msg[i+3])
		i += 4
	case 2: // Domain
		if i >= len(msg) {
			return fmt.Errorf("invalid domain length")
		}
		domainLen := int(msg[i])
		i++
		if i+domainLen > len(msg) {
			return fmt.Errorf("invalid domain")
		}
		host = string(msg[i : i+domainLen])
		i += domainLen
	case 3: // IPv6
		if i+16 > len(msg) {
			return fmt.Errorf("invalid IPv6 address")
		}
		ipv6Parts := make([]string, 8)
		for j := 0; j < 8; j++ {
			part := binary.BigEndian.Uint16(msg[i+j*2 : i+j*2+2])
			ipv6Parts[j] = fmt.Sprintf("%x", part)
		}
		host = strings.Join(ipv6Parts, ":")
		i += 16
	default:
		return fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Send response
	response := []byte{version, 0}
	if err := ws.WriteMessage(websocket.BinaryMessage, response); err != nil {
		return err
	}

	// Connect to target
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, targetPort))
	if err != nil {
		return fmt.Errorf("failed to connect to target: %v", err)
	}
	defer targetConn.Close()

	// Send initial data if any
	if i < len(msg) {
		if _, err := targetConn.Write(msg[i:]); err != nil {
			return err
		}
	}

	// Start bidirectional data transfer
	go func() {
		defer targetConn.Close()
		defer ws.Close()

		buffer := make([]byte, 4096)
		for {
			n, err := targetConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Println("Target read error:", err)
				}
				return
			}

			if err := ws.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil {
				log.Println("WebSocket write error:", err)
				return
			}
		}
	}()

	// Handle WebSocket messages and forward to target
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Println("WebSocket read error:", err)
			}
			break
		}

		if _, err := targetConn.Write(data); err != nil {
			log.Println("Target write error:", err)
			break
		}
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func GetConf(name string) string {
	c, err := fconf.NewFileConf("./set.ini")
	if err != nil {
		log.Println(err)
	}
	return c.String(name)
}
