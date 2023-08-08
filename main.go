package main

import (
  "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
  "io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/parnurzeal/gorequest"
)

func generateRandomKey(keySize int) []byte {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Error generating random key:", err)
	}
	return key
}

var secretKey = []byte(os.Getenv("SECRET_KEY"))

func main() {
	router := gin.Default()

  //fmt.Printf("%s\n", generateRandomKey(32))
  
	router.GET("/fetch", handleQRCodeScan)
  router.GET("/encrypt", encryptDiscordWebhookURL)
  router.Use(staticMiddleware())
  
	port := ":8080" // You can change this to the desired port
	log.Printf("Server running on port %s", port)
	router.Run(port)
}

func handleQRCodeScan(c *gin.Context) {
	location := c.Query("location")
	redir := c.Query("redir")

	// Logging the time and location to the console
	log.Printf("Time: %s, Location: %s", time.Now().Format("2006-01-02 15:04:05"), location)

	// Sending the data to Discord webhook
  webhookURL, err := decryptURL(c.Query("url"))
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid URL parameter")
		return
	}
  
  sendToDiscord(webhookURL, location, redir)

	// Redirecting to the provided URL
	c.Redirect(http.StatusFound, redir)
}

func sendToDiscord(webhookURL, location string, redir string) {
	request := gorequest.New()
	payload := map[string]string{
		"content": fmt.Sprintf("Time: %s\nLocation: %s\nRedirect URL: %s", time.Now().Format("2006-01-02 15:04:05"), location, redir),
	}

	resp, body, errs := request.Post(webhookURL).
		Send(payload).
		End()

	if errs != nil || resp.StatusCode != http.StatusNoContent {
		log.Printf("Error sending data to Discord: %v, %s", errs, body)
	}
}

func staticMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		fileServer := http.FileServer(http.Dir("static"))
		http.StripPrefix("/", fileServer).ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

// EncryptURL encrypts the Discord webhook URL using the secret key.
func encryptURL(url string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(url), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptURL decrypts the encrypted Discord webhook URL using the secret key.
func decryptURL(encryptedURL string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedURL)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	/*if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}*/

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func encryptDiscordWebhookURL(c *gin.Context) {
	// Get the actual Discord Webhook URL from the query parameter
	webhookURL := c.Query("url")

	// Encrypt the Discord Webhook URL using the secret key
	encryptedURL, err := encryptURL(webhookURL)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error encrypting URL")
    fmt.Printf("%s\n",err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"encryptedURL": encryptedURL,
	})
}