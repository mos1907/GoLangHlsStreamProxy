package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	jwtware "github.com/gofiber/jwt/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	db                    *gorm.DB
	tokenCache            = make(map[string]tokenInfo)
	tokenMutex            sync.RWMutex
	activeSessionsPerUser = make(map[string]map[string]time.Time)
	activeSessionsMutex   sync.RWMutex
	jwtSecret             = []byte("your_jwt_secret")
	sessionTimeout        = 24 * time.Hour
	streamTokenTimeout    = 5 * time.Minute
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
}

type StreamURL struct {
	ID       uint   `gorm:"primaryKey"`
	BaseURL  string `gorm:"not null"`
	EndPoint string `gorm:"not null"`
	UserID   uint   `gorm:"not null"`
}

type tokenInfo struct {
	Username  string
	SessionID string
	Expiry    time.Time
	IP        string
	UserAgent string
}

func main() {
	log.Println("Starting the application...")
	initDB()
	app := fiber.New()
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization",
		AllowCredentials: false,
		ExposeHeaders:    "Content-Length,Content-Type,X-New-Token",
	}))

	api := app.Group("/api")

	api.Post("/register", register)
	api.Post("/login", login)

	api.Use("/stream", jwtware.New(jwtware.Config{
		SigningKey: jwtSecret,
	}))
	api.Get("/stream", getStreamURL)
	api.Get("/streams", jwtware.New(jwtware.Config{
		SigningKey: jwtSecret,
	}), getAllStreams)
	api.Post("/update-stream", jwtware.New(jwtware.Config{
		SigningKey: jwtSecret,
	}), updateStreamURL)

	api.Get("/hls/:token/:streamID/*", streamHLS)

	log.Println("Server is starting on :8080")
	log.Fatal(app.Listen(":8080"))
}

func initDB() {
	log.Println("Initializing database...")
	var err error
	db, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect database:", err)
	}
	db.AutoMigrate(&User{}, &StreamURL{})
	log.Println("Database initialized successfully")
}

func register(c *fiber.Ctx) error {
	log.Println("Received registration request")
	var user User
	if err := c.BodyParser(&user); err != nil {
		log.Println("Failed to parse registration request:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Failed to hash password:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Cannot hash password"})
	}

	user.Password = string(hashedPassword)

	if err := db.Create(&user).Error; err != nil {
		log.Println("Failed to create user:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Cannot create user"})
	}

	log.Println("User registered successfully:", user.Username)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User created successfully"})
}

func login(c *fiber.Ctx) error {
	log.Println("Received login request")
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&loginData); err != nil {
		log.Println("Failed to parse login request:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
	}

	var user User
	if err := db.Where("username = ?", loginData.Username).First(&user).Error; err != nil {
		log.Println("User not found:", loginData.Username)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
		log.Println("Invalid password for user:", loginData.Username)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	sessionID := generateSessionID()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":  user.Username,
		"sessionID": sessionID,
		"exp":       time.Now().Add(sessionTimeout).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Println("Failed to generate token:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	activeSessionsMutex.Lock()
	if _, exists := activeSessionsPerUser[user.Username]; !exists {
		activeSessionsPerUser[user.Username] = make(map[string]time.Time)
	}
	activeSessionsPerUser[user.Username][sessionID] = time.Now().Add(sessionTimeout)
	activeSessionsMutex.Unlock()

	log.Println("User logged in successfully:", user.Username)
	return c.JSON(fiber.Map{"token": tokenString})
}

func getStreamURL(c *fiber.Ctx) error {
	log.Println("Received request to get stream URL")
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)
	sessionID := claims["sessionID"].(string)

	log.Printf("User: %s, SessionID: %s", username, sessionID)

	streamIDStr := c.Query("streamID")
	log.Printf("Requested stream ID: '%s'", streamIDStr)

	if streamIDStr == "" {
		log.Println("Stream ID is empty")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Stream ID is required"})
	}

	streamID, err := strconv.Atoi(streamIDStr)
	if err != nil {
		log.Printf("Invalid stream ID: %s", streamIDStr)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid stream ID"})
	}

	var userData User
	if err := db.Where("username = ?", username).First(&userData).Error; err != nil {
		log.Printf("User not found: %s, Error: %v", username, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	var streamURL StreamURL
	if err := db.Where("id = ? AND user_id = ?", streamID, userData.ID).First(&streamURL).Error; err != nil {
		log.Printf("Stream not found for user %s and stream ID %d, Error: %v", username, streamID, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Stream not found"})
	}

	streamToken := generateStreamToken(username, sessionID, c.IP(), c.Get("User-Agent"))

	proxyURL := fmt.Sprintf("http://%s/api/hls/%s/%d/%s", c.Hostname(), streamToken, streamID, streamURL.EndPoint)

	log.Printf("Generated proxy URL for user %s and stream ID %d: %s", username, streamID, proxyURL)
	return c.JSON(fiber.Map{
		"stream_url": proxyURL,
		"token":      streamToken,
	})
}

func getAllStreams(c *fiber.Ctx) error {
	log.Println("Received request to get all streams")
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	var userData User
	if err := db.Where("username = ?", username).First(&userData).Error; err != nil {
		log.Println("User not found:", username)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	var streams []StreamURL
	if err := db.Where("user_id = ?", userData.ID).Find(&streams).Error; err != nil {
		log.Println("Failed to fetch streams for user:", username, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	log.Printf("Fetched %d streams for user: %s", len(streams), username)
	return c.JSON(fiber.Map{"streams": streams})
}

func updateStreamURL(c *fiber.Ctx) error {
	log.Println("Received request to update stream URL")
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	var userData User
	if err := db.Where("username = ?", username).First(&userData).Error; err != nil {
		log.Println("User not found:", username)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	var streamData struct {
		StreamID uint   `json:"streamID"`
		NewURL   string `json:"newUrl"`
	}
	if err := c.BodyParser(&streamData); err != nil {
		log.Println("Failed to parse stream update request:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
	}

	baseURL, endPoint := splitURL(streamData.NewURL)

	var streamURL StreamURL
	result := db.Where("id = ? AND user_id = ?", streamData.StreamID, userData.ID).First(&streamURL)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			log.Printf("Creating new stream for user %s: %d", username, streamData.StreamID)
			streamURL = StreamURL{UserID: userData.ID, BaseURL: baseURL, EndPoint: endPoint}
			db.Create(&streamURL)
		} else {
			log.Println("Database error while updating stream:", result.Error)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
		}
	} else {
		log.Printf("Updating existing stream for user %s: %d", username, streamData.StreamID)
		streamURL.BaseURL = baseURL
		streamURL.EndPoint = endPoint
		db.Save(&streamURL)
	}

	log.Printf("Stream URL updated successfully for user %s: %d", username, streamData.StreamID)
	return c.JSON(fiber.Map{"message": "Stream URL updated successfully"})
}

func streamHLS(c *fiber.Ctx) error {
	log.Println("Received HLS stream request")
	token := c.Params("token")
	streamIDStr := c.Params("streamID")

	streamID, err := strconv.Atoi(streamIDStr)
	if err != nil {
		log.Printf("Invalid stream ID: %s", streamIDStr)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid stream ID"})
	}

	info, valid, newToken := isValidToken(token, c.IP(), c.Get("User-Agent"))
	if !valid {
		log.Printf("Invalid token for stream request: %s", token)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
	}

	if newToken != "" {
		log.Printf("Issuing new token for stream request: %s", newToken)
		c.Set("X-New-Token", newToken)
		token = newToken
	} else {
		newToken = generateStreamToken(info.Username, info.SessionID, c.IP(), c.Get("User-Agent"))
		c.Set("X-New-Token", newToken)
	}

	var streamURL StreamURL
	if err := db.Where("id = ? AND user_id = ?", streamID, getUserIDFromUsername(info.Username)).First(&streamURL).Error; err != nil {
		log.Printf("Stream URL not found for user %s and stream ID %d", info.Username, streamID)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Stream URL not found"})
	}

	path := c.Params("*")
	url := streamURL.BaseURL + "/" + path

	log.Printf("Fetching content from URL: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Failed to fetch content from URL %s: %v", url, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch content"})
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	c.Set("Content-Type", contentType)

	if strings.HasSuffix(path, ".m3u8") {
		log.Println("Modifying m3u8 content")
		modifiedContent, err := modifyM3U8(resp.Body, token, streamIDStr)
		if err != nil {
			log.Printf("Failed to modify m3u8 content: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to modify m3u8"})
		}
		return c.Send(modifiedContent)
	}

	log.Println("Streaming content")
	_, err = io.Copy(c.Response().BodyWriter(), resp.Body)
	if err != nil {
		log.Printf("Failed to stream content: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to stream content"})
	}

	return nil
}

func modifyM3U8(content io.Reader, token, streamID string) ([]byte, error) {
	scanner := bufio.NewScanner(content)
	var modifiedContent bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			modifiedContent.WriteString(line + "\n")
		} else if strings.HasSuffix(line, ".ts") || strings.HasSuffix(line, ".m3u8") {
			if !strings.HasPrefix(line, "http") {
				modifiedLine := fmt.Sprintf("/api/hls/%s/%s/%s\n", token, streamID, line)
				modifiedContent.WriteString(modifiedLine)
			} else {
				modifiedContent.WriteString(line + "\n")
			}
		} else {
			modifiedContent.WriteString(line + "\n")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning m3u8 content: %v", err)
		return nil, err
	}

	return modifiedContent.Bytes(), nil
}

func generateStreamToken(username, sessionID, ip, userAgent string) string {
	tokenData := fmt.Sprintf("%s|%s|%s|%s|%d", username, sessionID, ip, userAgent, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(tokenData))
	token := hex.EncodeToString(hash[:])

	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	tokenCache[token] = tokenInfo{
		Username:  username,
		SessionID: sessionID,
		Expiry:    time.Now().Add(streamTokenTimeout),
		IP:        ip,
		UserAgent: userAgent,
	}

	log.Printf("Generated stream token for user %s: %s", username, token)
	return token
}

func isValidToken(token, ip, userAgent string) (tokenInfo, bool, string) {
	tokenMutex.RLock()
	info, exists := tokenCache[token]
	tokenMutex.RUnlock()

	if !exists {
		log.Printf("Token not found in cache: %s", token)
		return tokenInfo{}, false, ""
	}

	now := time.Now()

	activeSessionsMutex.RLock()
	sessionExpiry, sessionExists := activeSessionsPerUser[info.Username][info.SessionID]
	activeSessionsMutex.RUnlock()

	if !sessionExists || now.After(sessionExpiry) {
		log.Printf("Session expired for user %s", info.Username)
		return tokenInfo{}, false, ""
	}

	if now.After(info.Expiry) {
		if info.IP == ip && info.UserAgent == userAgent {
			newToken := generateStreamToken(info.Username, info.SessionID, ip, userAgent)
			log.Printf("Refreshed expired token for user %s: %s", info.Username, newToken)
			return tokenCache[newToken], true, newToken
		}
		log.Printf("Token expired for user %s", info.Username)
		return tokenInfo{}, false, ""
	}

	if info.IP == ip && info.UserAgent == userAgent {
		log.Printf("Valid token for user %s", info.Username)
		return info, true, ""
	}

	log.Printf("IP or User-Agent mismatch for token of user %s", info.Username)
	return tokenInfo{}, false, ""
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getUserIDFromUsername(username string) uint {
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		log.Printf("Failed to get user ID for username %s: %v", username, err)
		return 0
	}
	return user.ID
}

func splitURL(url string) (string, string) {
	lastSlashIndex := strings.LastIndex(url, "/")
	if lastSlashIndex == -1 {
		return url, ""
	}
	return url[:lastSlashIndex], url[lastSlashIndex+1:]
}
