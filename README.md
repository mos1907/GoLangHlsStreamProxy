---
title: "Building a Secure HLS Stream Manager with Go"
date: 2024-10-18
lastmod: 2024-10-18
draft: false
authors: ["Murat"]
tags: ["HLS","Stream", "Jwt Token","HLS Proxy","Proxy"]
categories: ["Broadcast IT"]
description: "Building a Secure HLS Stream Manager with Go"
lightgallery: true
featuredImage: "hls.png"
---

# Comprehensive HLS Stream Manager with Go: A Detailed Backend Analysis

## Introduction

In this blog post, we'll dive deep into the backend implementation of a secure HLS (HTTP Live Streaming) Stream Manager developed using the Go programming language. Our project is designed to manage and serve live video streams securely to users.

## Technologies Used

Our project leverages the following key technologies:

- **Go**: The primary programming language
- **Fiber**: A fast and efficient HTTP web framework
- **GORM**: An ORM (Object-Relational Mapping) library for Go
- **JWT**: JSON Web Tokens for authentication
- **SQLite**: As the database
- **bcrypt**: For password hashing

## Project Structure

Our project consists of four main components:

1. User Management
2. Stream URL Management
3. Authentication and Authorization
4. HLS Stream Proxy

Let's examine each component in detail.

### 1. User Management

User management is handled by the `User` struct and related functions:

```go
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
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
```

This section handles user registration and login processes. Passwords are securely hashed using bcrypt, and JWT tokens are generated for authenticated sessions.

### 2. Stream URL Management

Stream URLs are managed using the `StreamURL` struct:

```go
type StreamURL struct {
	ID       uint   `gorm:"primaryKey"`
	BaseURL  string `gorm:"not null"`
	EndPoint string `gorm:"not null"`
	UserID   uint   `gorm:"not null"`
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
```

This section allows users to manage their stream URLs. Users can list their streams and update them as needed.

### 3. Authentication and Authorization

A secure authentication system is implemented using JWT:

```go
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
```

This section generates and validates short-lived tokens for stream access, ensuring secure access for each request.

### 4. HLS Stream Proxy

A proxy system is implemented to serve HLS streams securely:

```go
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
```

This section ensures secure serving of HLS streams. The `streamHLS` function handles incoming requests and performs necessary security checks. The `modifyM3U8` function dynamically modifies m3u8 files to create secure URLs for each segment.

## Security Measures

Our project implements various security measures:

1. **Password Hashing**: User passwords are securely hashed using bcrypt before storage.
2. **JWT Authentication**: User sessions are managed using JWT tokens.
3. **Short-lived Stream Tokens**: Special short-lived tokens are generated for each HLS request.
4. **IP and User-Agent Verification**: IP address and User-Agent information are checked during token validation to prevent token theft and unauthorized access.

5. **HTTPS Support**: The project can be configured to use HTTPS, ensuring all communications are encrypted.

## Performance and Scalability

Our project leverages Go's concurrency features to provide high performance. The fast route handling capability of the Fiber framework allows the application to process a large number of simultaneous requests.

The use of GORM for database operations facilitates the optimization and management of database queries. In future stages, database scalability techniques such as sharding or replication can be implemented to handle increased load.

The stream proxy system is designed to efficiently handle and modify HLS streams, allowing for smooth playback even under high load conditions.

## Conclusion and Future Enhancements

This HLS Stream Manager project demonstrates a secure and scalable backend solution using Go's powerful features. The project is suitable for scenarios requiring secure management and delivery of live video streams.

Future enhancements could include:

1. Advanced analytics and monitoring features
2. Multi-CDN support
3. Transition to a cloud-native architecture for automatic scaling
4. Real-time notifications using WebSockets
5. API rate limiting and more advanced security measures

Some specific areas for improvement and expansion include:

- **Caching**: Implement a caching layer (e.g., Redis) to reduce database load and improve response times for frequently accessed data.
- **Load Balancing**: Introduce a load balancer to distribute traffic across multiple instances of the application for improved performance and reliability.
- **Containerization**: Dockerize the application to simplify deployment and scaling.
- **Metrics and Logging**: Integrate with monitoring tools like Prometheus and logging solutions like ELK stack for better observability.
- **API Documentation**: Implement Swagger or similar tools for automated API documentation.
- **Testing**: Expand unit and integration test coverage to ensure reliability as the project grows.

This project provides a solid foundation for secure video streaming solutions in modern web applications. Its modular design and use of Go's concurrency model make it well-suited for high-performance, real-time streaming scenarios.

By focusing on security, performance, and scalability from the outset, this HLS Stream Manager sets the stage for a robust, production-ready streaming solution that can evolve to meet growing demands and changing requirements in the dynamic world of video streaming.


## Testing and Using the API with Postman

For testing and using the HLS Stream Manager API, you can follow these guidelines using Postman:

1. **Setting Up Postman**
   - Open Postman and create a new collection named "HLS Stream Manager API".
   - Set the base URL to `http://localhost:8080/api` in your collection variables.

2. **User Registration**
   - Method: POST
   - URL: `{{baseUrl}}/register`
   - Body (raw JSON):
     ```json
     {
       "username": "testuser",
       "password": "securepassword"
     }
     ```
   - Send the request and verify that you receive a successful response.

3. **User Login**
   - Method: POST
   - URL: `{{baseUrl}}/login`
   - Body (raw JSON):
     ```json
     {
       "username": "testuser",
       "password": "securepassword"
     }
     ```
   - Send the request and save the returned JWT token.

4. **Set Up Authentication**
   - In the Authorization tab of your collection, select "Bearer Token" and paste the JWT token you received from the login request.

5. **Get All Streams**
   - Method: GET
   - URL: `{{baseUrl}}/streams`
   - Ensure the Bearer Token is set in the Authorization tab.
   - Send the request to retrieve all streams for the authenticated user.

6. **Update Stream URL**
   - Method: POST
   - URL: `{{baseUrl}}/update-stream`
   - Body (raw JSON):
     ```json
     {
       "streamID": 1,
       "newUrl": "https://example.com/new_stream.m3u8"
     }
     ```
   - Send the request to update an existing stream or add a new one.

7. **Get Stream URL**
   - Method: GET
   - URL: `{{baseUrl}}/stream?streamID=1`
   - Send the request to get the secure URL for a specific stream.

8. **Access HLS Stream**
   - Use the URL returned from the previous request in a compatible HLS player or directly in a web browser to test the stream access.

Remember to handle the JWT token securely and never share it publicly. For each request requiring authentication, ensure that the Bearer Token is correctly set in the Authorization header.

By following these steps, you can thoroughly test and interact with the HLS Stream Manager API using Postman. This process will help you understand the flow of operations and verify the functionality of each endpoint.
