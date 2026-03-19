Looking at the provided code, I need to analyze the `User` class and create comprehensive unit tests. I notice there are some differences from the existing tests - particularly the SQL query now includes `DROP DATABASE 1` which appears to be a SQL injection vulnerability in the code itself.

Let me create the unit tests based on the provided code:

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
    private static final String TEST_SECRET = "testSecretKeyForJWTTestingMinimum32Bytes";

    private ByteArrayOutputStream outContent;
    private ByteArrayOutputStream errContent;
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User("1", "testUser", "hashedPassword");
        setupOutputCapture();
    }

    // Helper method to set up output stream capture
    private void setupOutputCapture() {
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
        originalOut = System.out;
        originalErr = System.err;
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    // Helper method to restore original output streams
    private void restoreOutputStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    // Helper method to create a valid JWT token
    private String createValidToken(String username, String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.builder()
                .setSubject(username)
                .signWith(key)
                .compact();
    }

    // Helper method to set up mock database connection
    private void setupMockDatabaseConnection() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
    }

    // ==================== Constructor Tests ====================

    /**
     * Test that User constructor correctly initializes all fields
     */
    @Test
    void constructor_WithValidParameters_ShouldInitializeAllFields() {
        String expectedId = "testId";
        String expectedUsername = "testUsername";
        String expectedPassword = "testPassword";

        User user = new User(expectedId, expectedUsername, expectedPassword);

        assertEquals(expectedId, user.id, "User id should be initialized correctly");
        assertEquals(expectedUsername, user.username, "User username should be initialized correctly");
        assertEquals(expectedPassword, user.hashedPassword, "User hashedPassword should be initialized correctly");
    }

    /**
     * Test that User constructor handles null values
     */
    @Test
    void constructor_WithNullValues_ShouldAcceptNullFields() {
        User user = new User(null, null, null);

        assertNull(user.id, "User id should be null when initialized with null");
        assertNull(user.username, "User username should be null when initialized with null");
        assertNull(user.hashedPassword, "User hashedPassword should be null when initialized with null");
    }

    /**
     * Test that User constructor handles empty strings
     */
    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyFields() {
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
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
        
        restoreOutputStreams();
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
        
        restoreOutputStreams();
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
        
        restoreOutputStreams();
    }

    /**
     * Test that same user generates consistent token structure
     */
    @Test
    void token_ForSameUser_ShouldGenerateConsistentStructure() {
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        // Both tokens should be valid but may differ due to timing
        assertNotNull(token1, "First token should not be null");
        assertNotNull(token2, "Second token should not be null");
        assertEquals(3, token1.split("\\.").length, "First token should have three parts");
        assertEquals(3, token2.split("\\.").length, "Second token should have three parts");
        
        restoreOutputStreams();
    }

    /**
     * Test token generation with minimum length secret
     */
    @Test
    void token_WithMinimumLengthSecret_ShouldGenerateValidToken() {
        String minSecret = "12345678901234567890123456789012"; // 32 bytes minimum for HMAC-SHA
        
        String token = testUser.token(minSecret);

        assertNotNull(token, "Token should be generated with minimum length secret");
        
        restoreOutputStreams();
    }

    // ==================== assertAuth Tests ====================

    /**
     * Test that assertAuth does not throw for valid token
     */
    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        String token = testUser.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token), 
                "assertAuth should not throw exception for valid token");
        
        restoreOutputStreams();
    }

    /**
     * Test that assertAuth throws Unauthorized for invalid token
     */
    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        String invalidToken = "invalidToken";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken), 
                "assertAuth should throw Unauthorized for invalid token");
        
        restoreOutputStreams();
    }

    /**
     * Test that assertAuth throws Unauthorized for modified token
     */
    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), 
                "assertAuth should throw Unauthorized for modified token");
        
        restoreOutputStreams();
    }

    /**
     * Test that assertAuth throws Unauthorized for token signed with different secret
     */
    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForJWTTestingMinimum32Bytes";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), 
                "assertAuth should throw Unauthorized for token signed with different secret");
        
        restoreOutputStreams();
    }

    /**
     * Test that assertAuth throws Unauthorized for empty token
     */
    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""), 
                "assertAuth should throw Unauthorized for empty token");
        
        restoreOutputStreams();
    }

    /**
     * Test that assertAuth throws Unauthorized for null token
     */
    @Test
    void assertAuth_WithNullToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, null), 
                "assertAuth should throw Unauthorized for null token");
        
        restoreOutputStreams();
    }

    /**
     * Test that assertAuth prints stack trace on exception
     */
    @Test
    void assertAuth_OnException_ShouldPrintStackTrace() {
        String invalidToken = "invalidToken";

        try {
            User.assertAuth(TEST_SECRET, invalidToken);
        } catch (Unauthorized e) {
            // Expected exception
        }

        String errorOutput = errContent.toString();
        assertTrue(errorOutput.length() > 0, "assertAuth should print stack trace on exception");
        
        restoreOutputStreams();
    }

    // ==================== fetch Tests ====================

    /**
     * Test that fetch returns user when user exists in database
     */
    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        String username = "existingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("hashedPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user for existing username");
            assertEquals(username, result.username, "Fetched user should have correct username");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch returns null when user does not exist
     */
    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        String username = "nonExistingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for non-existing username");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch returns null when database exception occurs
     */
    @Test
    void fetch_WithDatabaseException_ShouldReturnNull() throws Exception {
        String username = "exceptionUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new RuntimeException("Database connection failed"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when database exception occurs");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch prints "Opened database successfully" message
     */
    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            String output = outContent.toString();
            assertTrue(output.contains("Opened database successfully"), 
                    "Fetch should print 'Opened database successfully' message");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch prints the SQL query
     */
    @Test
    void fetch_ShouldPrintSQLQuery() throws Exception {
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            String output = outContent.toString();
            assertTrue(output.contains("select * from users where username = '" + username + "' limit 1"), 
                    "Fetch should print the SQL query");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch closes the connection after execution
     */
    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch handles exception and prints error message
     */
    @Test
    void fetch_OnException_ShouldPrintErrorMessage() throws Exception {
        String username = "exceptionUser";
        String errorMessage = "Test database exception";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new RuntimeException(errorMessage));

            User.fetch(username);

            String errorOutput = errContent.toString();
            assertTrue(errorOutput.contains(errorMessage), 
                    "Fetch should print the exception message to stderr");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch correctly maps all user fields from ResultSet
     */
    @Test
    void fetch_ShouldCorrectlyMapAllUserFields() throws Exception {
        String expectedId = "userId123";
        String expectedUsername = "mappedUser";
        String expectedPassword = "mappedPassword";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(expectedId);
            when(mockResultSet.getString("username")).thenReturn(expectedUsername);
            when(mockResultSet.getString("password")).thenReturn(expectedPassword);

            User result = User.fetch(expectedUsername);

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedId, result.id, "User id should be correctly mapped");
            assertEquals(expectedUsername, result.username, "User username should be correctly mapped");
            assertEquals(expectedPassword, result.hashedPassword, "User hashedPassword should be correctly mapped");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch executes query containing DROP DATABASE (vulnerability test)
     */
    @Test
    void fetch_QueryShouldContainDropDatabase_VulnerabilityCheck() throws Exception {
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            String output = outContent.toString();
            // This test documents the vulnerability in the code
            assertTrue(output.contains("DROP DATABASE"), 
                    "Query contains DROP DATABASE - this is a security vulnerability");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test fetch with special characters in username
     */
    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldExecuteQuery() throws Exception {
        String username = "user'test";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            // The query is executed regardless of special characters (SQL injection vulnerability)
            verify(mockStatement).executeQuery(contains(username));
        }
        
        restoreOutputStreams();
    }

    /**
     * Test fetch with empty username
     */
    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQueryAndReturnNull() throws Exception {
        String username = "";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for empty username when no user found");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test fetch when ResultSet getString throws exception
     */
    @Test
    void fetch_WhenResultSetThrowsException_ShouldReturnNull() throws Exception {
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenThrow(new RuntimeException("ResultSet error"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when ResultSet throws exception");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test fetch when createStatement throws exception
     */
    @Test
    void fetch_WhenCreateStatementThrowsException_ShouldReturnNull() throws Exception {
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when createStatement throws exception");
        }
        
        restoreOutputStreams();
    }

    /**
     * Test that fetch returns user with correct values when multiple rows exist
     */
    @Test
    void fetch_WithMultipleRows_ShouldReturnFirstRow() throws Exception {
        String username = "duplicateUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("firstId");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("firstPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return the first user");
            assertEquals("firstId", result.id, "Should return the first row's user id");
        }
        
        restoreOutputStreams();
    }
}
```
