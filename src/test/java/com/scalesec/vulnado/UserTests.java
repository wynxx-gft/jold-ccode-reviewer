```java
package com.scalesec.vulnado;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

class UserTest {

    @Mock
    private Connection mockConnection;
    @Mock
    private Statement mockStatement;
    @Mock
    private ResultSet mockResultSet;

    private User testUser;
    private static final String TEST_SECRET = "testSecretKeyForJWTTestingThatIsLongEnough";

    private ByteArrayOutputStream outContent;
    private ByteArrayOutputStream errContent;
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User("1", "testUser", "hashedPassword");
        
        // Capture console output for testing
        originalOut = System.out;
        originalErr = System.err;
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
    }

    // Helper method to capture standard output
    private void captureOutput() {
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    // Helper method to restore standard output
    private void restoreOutput() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    // Helper method to create a valid JWT token for testing
    private String createValidToken(String username, String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.builder()
                .setSubject(username)
                .signWith(key)
                .compact();
    }

    // Helper method to setup mock database connection
    private void setupMockDatabaseConnection() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
    }

    // ==================== Constructor Tests ====================

    /**
     * Test that User constructor correctly initializes all fields
     */
    @Test
    void constructor_WithValidParameters_ShouldInitializeAllFields() {
        String expectedId = "123";
        String expectedUsername = "john_doe";
        String expectedPassword = "hashed_pwd_123";

        User user = new User(expectedId, expectedUsername, expectedPassword);

        assertEquals(expectedId, user.id, "User id should be initialized correctly");
        assertEquals(expectedUsername, user.username, "User username should be initialized correctly");
        assertEquals(expectedPassword, user.hashedPassword, "User hashedPassword should be initialized correctly");
    }

    /**
     * Test that User constructor handles null values
     */
    @Test
    void constructor_WithNullValues_ShouldAcceptNullValues() {
        User user = new User(null, null, null);

        assertNull(user.id, "User id should be null when initialized with null");
        assertNull(user.username, "User username should be null when initialized with null");
        assertNull(user.hashedPassword, "User hashedPassword should be null when initialized with null");
    }

    /**
     * Test that User constructor handles empty strings
     */
    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyStrings() {
        User user = new User("", "", "");

        assertEquals("", user.id, "User id should be empty string");
        assertEquals("", user.username, "User username should be empty string");
        assertEquals("", user.hashedPassword, "User hashedPassword should be empty string");
    }

    // ==================== Token Generation Tests ====================

    /**
     * Test that token method generates a valid JWT token
     */
    @Test
    void token_WithValidSecret_ShouldGenerateValidJWT() {
        String token = testUser.token(TEST_SECRET);

        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots (header.payload.signature)");
    }

    /**
     * Test that token contains the correct username as subject
     */
    @Test
    void token_ShouldContainCorrectUsernameAsSubject() {
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        
        String subject = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();

        assertEquals(testUser.username, subject, "Token subject should match the username");
    }

    /**
     * Test that different users generate different tokens
     */
    @Test
    void token_ForDifferentUsers_ShouldGenerateUniqueTokens() {
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    /**
     * Test that same user generates consistent token structure
     */
    @Test
    void token_ForSameUser_ShouldGenerateValidTokenStructure() {
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        // Both tokens should be valid and parseable
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        
        assertDoesNotThrow(() -> Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token1),
                "First token should be parseable");
        assertDoesNotThrow(() -> Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token2),
                "Second token should be parseable");
    }

    /**
     * Test token generation with different secrets produces different tokens
     */
    @Test
    void token_WithDifferentSecrets_ShouldGenerateDifferentTokens() {
        String secret1 = "firstSecretKeyThatIsLongEnoughForHMAC";
        String secret2 = "secondSecretKeyThatIsLongEnoughForHMAC";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Tokens generated with different secrets should be different");
    }

    // ==================== assertAuth Tests ====================

    /**
     * Test that assertAuth does not throw exception for valid token
     */
    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        String token = testUser.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token),
                "assertAuth should not throw exception for valid token");
    }

    /**
     * Test that assertAuth throws Unauthorized for invalid token
     */
    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        String invalidToken = "invalid.token.here";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken),
                "assertAuth should throw Unauthorized for invalid token");
    }

    /**
     * Test that assertAuth throws Unauthorized for tampered token
     */
    @Test
    void assertAuth_WithTamperedToken_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String tamperedToken = token.substring(0, token.length() - 5) + "XXXXX";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, tamperedToken),
                "assertAuth should throw Unauthorized for tampered token");
    }

    /**
     * Test that assertAuth throws Unauthorized for wrong secret
     */
    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "differentSecretKeyThatIsLongEnough";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token),
                "assertAuth should throw Unauthorized when using wrong secret");
    }

    /**
     * Test that assertAuth throws Unauthorized for null token
     */
    @Test
    void assertAuth_WithNullToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, null),
                "assertAuth should throw Unauthorized for null token");
    }

    /**
     * Test that assertAuth throws Unauthorized for empty token
     */
    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""),
                "assertAuth should throw Unauthorized for empty token");
    }

    /**
     * Test that assertAuth prints stack trace on exception
     */
    @Test
    void assertAuth_OnException_ShouldPrintStackTrace() {
        captureOutput();
        try {
            String invalidToken = "invalid.token";
            
            try {
                User.assertAuth(TEST_SECRET, invalidToken);
            } catch (Unauthorized e) {
                // Expected exception
            }

            assertTrue(errContent.toString().length() > 0,
                    "assertAuth should print stack trace to stderr on exception");
        } finally {
            restoreOutput();
        }
    }

    // ==================== fetch Method Tests ====================

    /**
     * Test that fetch returns user when user exists in database
     */
    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        String username = "existingUser";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("hashedPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user for existing username");
            assertEquals(username, result.username, "Fetched user should have correct username");
            assertEquals("1", result.id, "Fetched user should have correct id");
            assertEquals("hashedPassword", result.hashedPassword, "Fetched user should have correct password");
        }
    }

    /**
     * Test that fetch returns null when user does not exist
     */
    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        String username = "nonExistingUser";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for non-existing username");
        }
    }

    /**
     * Test that fetch returns null when database exception occurs
     */
    @Test
    void fetch_WithDatabaseException_ShouldReturnNull() {
        String username = "exceptionUser";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenThrow(new RuntimeException("Database connection failed"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when database exception occurs");
        }
    }

    /**
     * Test that fetch prints "Opened database successfully" message
     */
    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        captureOutput();
        try {
            try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
                postgresMock.when(Postgres::connection).thenReturn(mockConnection);
                setupMockDatabaseConnection();
                when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
                when(mockResultSet.next()).thenReturn(false);

                User.fetch("testUser");

                assertTrue(outContent.toString().contains("Opened database successfully"),
                        "Fetch should print 'Opened database successfully' message");
            }
        } finally {
            restoreOutput();
        }
    }

    /**
     * Test that fetch prints the executed query to console
     */
    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        captureOutput();
        try {
            String username = "testUser";
            try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
                postgresMock.when(Postgres::connection).thenReturn(mockConnection);
                setupMockDatabaseConnection();
                when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
                when(mockResultSet.next()).thenReturn(false);

                User.fetch(username);

                String output = outContent.toString();
                assertTrue(output.contains("select * from users where username"),
                        "Fetch should print the SQL query to console");
            }
        } finally {
            restoreOutput();
        }
    }

    /**
     * Test that fetch closes connection after execution
     */
    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
    }

    /**
     * Test that fetch handles exception and prints error message
     */
    @Test
    void fetch_OnException_ShouldPrintErrorMessage() {
        captureOutput();
        try {
            String username = "exceptionUser";
            RuntimeException testException = new RuntimeException("Test database exception");
            
            try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
                postgresMock.when(Postgres::connection).thenThrow(testException);

                User result = User.fetch(username);

                assertNull(result, "Fetch should return null when an exception occurs");
                assertTrue(errContent.toString().contains("Test database exception"),
                        "Fetch should print the exception message to stderr");
            }
        } finally {
            restoreOutput();
        }
    }

    /**
     * Test that fetch constructs SQL query with username - demonstrates SQL injection vulnerability
     * Note: This test documents the existing vulnerability in the code
     */
    @Test
    void fetch_ShouldIncludeUsernameInQuery_SQLInjectionVulnerability() throws Exception {
        String username = "testUser";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            // Verify the query contains the username directly (SQL injection vulnerable)
            verify(mockStatement).executeQuery(contains(username));
        }
    }

    /**
     * Test that fetch query includes DROP DATABASE statement - documents vulnerability
     * Note: This test documents a critical security issue in the code
     */
    @Test
    void fetch_QueryContainsDropDatabase_SecurityVulnerability() throws Exception {
        captureOutput();
        try {
            try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
                postgresMock.when(Postgres::connection).thenReturn(mockConnection);
                setupMockDatabaseConnection();
                when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
                when(mockResultSet.next()).thenReturn(false);

                User.fetch("anyUser");

                String output = outContent.toString();
                assertTrue(output.contains("DROP DATABASE"),
                        "The query contains DROP DATABASE - this is a critical security vulnerability");
            }
        } finally {
            restoreOutput();
        }
    }

    /**
     * Test that fetch handles SQL injection attempt in username
     */
    @Test
    void fetch_WithSQLInjectionUsername_ShouldExecuteInjectedQuery() throws Exception {
        String maliciousUsername = "user' OR '1'='1";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(maliciousUsername);

            // This verifies the vulnerability - malicious input is passed directly to query
            verify(mockStatement).executeQuery(contains(maliciousUsername));
        }
    }

    /**
     * Test that fetch returns first user when multiple results exist
     */
    @Test
    void fetch_WithMultipleResults_ShouldReturnFirstUser() throws Exception {
        String username = "duplicateUser";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("password1");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user when results exist");
            assertEquals("1", result.id, "Fetch should return the first user");
        }
    }

    /**
     * Test that fetch handles special characters in username
     */
    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldIncludeInQuery() throws Exception {
        String username = "user@domain.com";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            verify(mockStatement).executeQuery(contains(username));
        }
    }

    /**
     * Test that fetch handles empty username
     */
    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQueryWithEmptyString() throws Exception {
        String username = "";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for empty username when no user found");
            verify(mockStatement).executeQuery(anyString());
        }
    }

    /**
     * Test that fetch handles null result set values
     */
    @Test
    void fetch_WithNullResultSetValues_ShouldCreateUserWithNullValues() throws Exception {
        String username = "nullUser";
        
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(null);
            when(mockResultSet.getString("username")).thenReturn(null);
            when(mockResultSet.getString("password")).thenReturn(null);

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user object even with null values");
            assertNull(result.id, "User id should be null");
            assertNull(result.username, "User username should be null");
            assertNull(result.hashedPassword, "User hashedPassword should be null");
        }
    }

    /**
     * Test that fetch handles statement creation exception
     */
    @Test
    void fetch_WhenStatementCreationFails_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when statement creation fails");
        }
    }

    /**
     * Test that fetch handles query execution exception
     */
    @Test
    void fetch_WhenQueryExecutionFails_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when query execution fails");
        }
    }

    // ==================== Integration-style Tests ====================

    /**
     * Test the complete authentication flow: generate token and verify
     */
    @Test
    void tokenAndAssertAuth_FullAuthenticationFlow_ShouldSucceed() {
        User user = new User("1", "integrationTestUser", "password");
        
        String token = user.token(TEST_SECRET);
        
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token),
                "Full authentication flow should succeed with matching token and secret");
    }

    /**
     * Test that different users can authenticate independently
     */
    @Test
    void tokenAndAssertAuth_MultiplUsersIndependently_ShouldSucceed() {
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token1),
                "First user authentication should succeed");
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token2),
                "Second user authentication should succeed");
    }
}
```
