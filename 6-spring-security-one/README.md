# Spring Security One - JWT Authentication with Spring Boot 3.x

A comprehensive Spring Security implementation featuring JWT authentication, refresh tokens, and OAuth2 configuration.

## Table of Contents
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Authentication Flow](#authentication-flow)
- [API Endpoints](#api-endpoints)
- [Setup Instructions](#setup-instructions)

## Technology Stack
- **Java**: JDK 17+
- **Framework**: Spring Boot 3.x
- **Security**: Spring Security 6.x
- **Authentication**: JWT, OAuth2
- **Database**: (Configured in application.yml)
- **Build Tool**: Maven

## Project Structure

### Core Components
```
src/
├── main/
│   ├── java/
│   │   └── com/sakcode/securityone/
│   │       ├── Application.java            # Main application class
│   │       ├── config/                     # Security configurations
│   │       │   ├── JwtAuthEntryPoint.java  # Handles auth exceptions
│   │       │   ├── JwtAuthFilter.java      # JWT validation filter
│   │       │   ├── JwtConfig.java          # JWT configuration
│   │       │   ├── OAuth2Config.java       # OAuth2 configuration  
│   │       │   ├── PasswordConfig.java     # Password encoder config
│   │       │   └── SecurityConfig.java     # Main security config
│   │       ├── controller/                 # API controllers
│   │       │   ├── AuthController.java     # Auth endpoints
│   │       │   └── TestController.java     # Test endpoints
│   │       ├── dto/                        # Data transfer objects
│   │       │   ├── request/                # Request DTOs
│   │       │   └── response/               # Response DTOs
│   │       ├── entity/                     # JPA entities
│   │       │   ├── BlacklistedToken.java   # Blacklisted JWT tokens
│   │       │   ├── RefreshToken.java       # Refresh tokens
│   │       │   └── User.java               # User entity
│   │       ├── handler/                    # Exception handlers
│   │       ├── repository/                 # Spring Data repositories
│   │       ├── service/                    # Business logic
│   │       └── util/                       # Utility classes
│   └── resources/
│       └── application.yml                 # Application config
└── test/                                   # Test classes
```

### Key Classes Explained

#### Security Configuration
- **SecurityConfig.java**: Main security configuration class
  - Configures HTTP security
  - Sets up authentication manager
  - Registers security filters
- **JwtAuthFilter.java**: Validates JWT tokens in requests
- **JwtAuthEntryPoint.java**: Handles unauthorized requests

#### Authentication Flow
1. User submits credentials via `/api/auth/signin`
2. System validates credentials and generates JWT + refresh token
3. Subsequent requests include JWT in Authorization header
4. JwtAuthFilter validates token for each request
5. Expired tokens can be refreshed via `/api/auth/refreshtoken`

#### Services
- **UserService.java**: Handles user registration and management
- **RefreshTokenService.java**: Manages refresh token lifecycle
- **TokenBlacklistService.java**: Tracks invalidated JWT tokens

## Detailed API Documentation

### Authentication Controller (`AuthController.java`)

#### `POST /api/auth/signin`
```java
@PostMapping("/signin")
public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest)
```
- **Parameters**:
  - `loginRequest`: Contains username/email and password
- **Flow**:
  1. Authenticates credentials via AuthenticationManager
  2. Generates JWT token
  3. Creates refresh token
  4. Returns JWT and refresh token in response
- **Response**: 
  ```json
  {
    "token": "JWT_TOKEN",
    "refreshToken": "REFRESH_TOKEN",
    "id": 1,
    "username": "user",
    "email": "user@example.com",
    "roles": ["ROLE_USER"]
  }
  ```

#### `POST /api/auth/signup`
```java
@PostMapping("/signup")
public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest signUpRequest)
```
- **Parameters**:
  - `signUpRequest`: Contains username, email, password, and roles
- **Flow**:
  1. Checks if username/email exists
  2. Creates new User entity
  3. Hashes password
  4. Saves user to database
- **Response**: 
  ```json
  {
    "message": "User registered successfully!"
  }
  ```

#### `POST /api/auth/refreshtoken`
```java
@PostMapping("/refreshtoken")
public ResponseEntity<?> refreshtoken(@Valid @RequestBody RefreshTokenRequest request)
```
- **Parameters**:
  - `request`: Contains refresh token
- **Flow**:
  1. Validates refresh token
  2. Generates new JWT
  3. Returns new token pair
- **Response**: 
  ```json
  {
    "token": "NEW_JWT_TOKEN",
    "refreshToken": "NEW_REFRESH_TOKEN"
  }
  ```

### Security Configuration (`SecurityConfig.java`)

#### Key Methods:
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
```
- Configures:
  - CSRF protection
  - Session management
  - Authentication provider
  - JWT filter
  - Authorization rules
  - Exception handling

```java
@Bean
public AuthenticationManager authenticationManager(...)
```
- Sets up authentication manager with:
  - UserDetailsService
  - Password encoder

### JWT Utilities (`JwtUtil.java`)

#### Key Methods:
```java
public String generateJwtToken(Authentication authentication)
```
- Generates JWT with:
  - Subject (username)
  - Issued at time
  - Expiration time
  - Signing key
  - Claims (roles)

```java
public boolean validateJwtToken(String authToken)
```
- Validates token:
  - Signature
  - Expiration
  - Claims

## Development Steps

1. **Setup Security Configuration**
   - Configure HTTP security rules
   - Set up authentication manager
   - Register JWT filter

2. **Implement JWT Generation**
   - Create token generation utility
   - Set expiration times
   - Configure signing key

3. **Create Authentication Endpoints**
   - Signin with JWT generation
   - Signup with user creation
   - Token refresh mechanism

4. **Implement Token Validation Filter**
   - Parse Authorization header
   - Validate token
   - Set authentication context

5. **Add Role-based Access Control**
   - Define role hierarchy
   - Secure endpoints by role
   - Test authorization

## Setup Instructions

### Prerequisites
- JDK 17+
- Maven
- Database (configure in application.yml)

### Running the Application
1. Configure database in `application.yml`
2. Build the project:
```bash
mvn clean install
```
3. Run the application:
```bash
mvn spring-boot:run
```

### Docker
The project includes a `docker-compose.yml` file for containerized deployment.

## Configuration
Key configuration options in `application.yml`:
- JWT secret and expiration
- Database connection
- OAuth2 client details
- CORS settings
