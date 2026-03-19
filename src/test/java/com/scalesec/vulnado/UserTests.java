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
    private static final String TEST_SECRET = "testSecretKeyForJWTTestingMustBeLongEnough";

    private ByteArrayOutputStream outContent;
    private ByteArrayOutputStream errContent;
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User("1", "testUser", "hashedPassword");
        
        // Capture console output for verification
        originalOut = System.out;
        originalErr = System.err;
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
    }

    // Helper method to capture stdout
    private void captureStdOut() {
        System.setOut(new PrintStream(outContent));
    }

    // Helper method to capture stderr
    private void captureStdErr() {
        System.setErr(new PrintStream(errContent));
    }

    // Helper method to restore console streams
    private void restoreConsoleStreams() {
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

    @Test
    void constructor_ShouldInitializeAllFields() {
        // Test that constructor properly initializes all user fields
        String expectedId = "123";
        String expectedUsername = "newUser";
        String expectedPassword = "secureHash";

        User user = new User(expectedId, expectedUsername, expectedPassword);

        assertEquals(expectedId, user.id, "User id should be initialized correctly");
        assertEquals(expectedUsername, user.username, "User username should be initialized correctly");
        assertEquals(expectedPassword, user.hashedPassword, "User hashedPassword should be initialized correctly");
    }

    @Test
    void constructor_WithNullValues_ShouldAcceptNullFields() {
        // Test that constructor accepts null values without throwing exception
        User user = new User(null, null, null);

        assertNull(user.id, "User id should be null when initialized with null");
        assertNull(user.username, "User username should be null when initialized with null");
        assertNull(user.hashedPassword, "User hashedPassword should be null when initialized with null");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyFields() {
        // Test that constructor accepts empty string values
        User user = new User("", "", "");

        assertEquals("", user.id, "User id should be empty string when initialized with empty string");
        assertEquals("", user.username, "User username should be empty string when initialized with empty string");
        assertEquals("", user.hashedPassword, "User hashedPassword should be empty string when initialized with empty string");
    }

    // ==================== Token Generation Tests ====================

    @Test
    void token_ShouldGenerateValidJWT() {
        // Test that token method generates a valid JWT structure
        String token = testUser.token(TEST_SECRET);
        
        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots (header.payload.signature)");
    }

    @Test
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        // Test that different users get different tokens
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    @Test
    void token_ShouldContainCorrectUsername() {
        // Test that the generated token contains the correct username as subject
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        
        assertEquals(testUser.username, subject, "Token should contain the correct username as subject");
    }

    @Test
    void token_WithDifferentSecrets_ShouldGenerateDifferentTokens() {
        // Test that same user with different secrets produces different tokens
        String secret1 = "secretKeyOneForTestingPurposes123";
        String secret2 = "secretKeyTwoForTestingPurposes456";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Same user with different secrets should produce different tokens");
    }

    @Test
    void token_ShouldBeConsistentForSameUserAndSecret() {
        // Test that token generation is deterministic for same inputs (excluding time-based claims)
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        // Note: Since there's no timestamp in the current implementation, tokens should be identical
        assertEquals(token1, token2, "Token generation should be consistent for same user and secret");
    }

    // ==================== assertAuth Tests ====================

    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        // Test that assertAuth accepts a valid token without throwing exception
        String token = testUser.token(TEST_SECRET);
        
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token), 
                "assertAuth should not throw exception for valid token");
    }

    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized for invalid token
        String invalidToken = "invalidToken";
        
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken), 
                "assertAuth should throw Unauthorized for invalid token");
    }

    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized for tampered token
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), 
                "assertAuth should throw Unauthorized for modified token");
    }

    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized when using wrong secret
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForTestingPurposes";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), 
                "assertAuth should throw Unauthorized when token is verified with wrong secret");
    }

    @Test
    void assertAuth_WithNullToken_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized for null token
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, null), 
                "assertAuth should throw Unauthorized for null token");
    }

    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized for empty token
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""), 
                "assertAuth should throw Unauthorized for empty token");
    }

    @Test
    void assertAuth_ShouldPrintStackTraceOnException() {
        // Test that assertAuth prints stack trace when exception occurs
        String invalidToken = "invalidToken";
        captureStdErr();

        try {
            User.assertAuth(TEST_SECRET, invalidToken);
        } catch (Unauthorized e) {
            // Expected exception
        }

        restoreConsoleStreams();
        assertTrue(errContent.toString().length() > 0, 
                "assertAuth should print stack trace to stderr on exception");
    }

    @Test
    void assertAuth_WithMalformedJWT_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized for malformed JWT
        String malformedToken = "header.payload"; // Missing signature part
        
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, malformedToken), 
                "assertAuth should throw Unauthorized for malformed JWT");
    }

    // ==================== Fetch Tests ====================

    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        // Test that fetch returns a user for existing username
        String username = "existingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("hashedPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user for existing username");
            assertEquals(username, result.username, "Fetched user should have correct username");
        }
    }

    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        // Test that fetch returns null for non-existing username
        String username = "nonExistingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for non-existing username");
        }
    }

    @Test
    void fetch_WithDatabaseException_ShouldReturnNull() throws Exception {
        // Test that fetch returns null when database exception occurs
        String username = "exceptionUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new RuntimeException("Database connection failed"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when database exception occurs");
        }
    }

    @Test
    void fetch_ShouldExecuteQueryWithSQLInjectionVulnerability() throws Exception {
        // Test that fetch executes the query containing the SQL injection payload
        // Note: This test documents the SQL injection vulnerability in the code
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            // Verify that the query includes the DROP DATABASE injection
            String expectedQuery = "select * from users where username = '" + username + "' limit 1 DROP DATABASE";
            verify(mockStatement).executeQuery(expectedQuery);
        }
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Test that fetch closes the database connection after execution
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
    }

    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        // Test that fetch prints the database opened message
        captureStdOut();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");
        }

        restoreConsoleStreams();
        assertTrue(outContent.toString().contains("Opened database successfully"), 
                "Fetch should print 'Opened database successfully' message");
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Test that fetch prints the executed query to console
        String username = "testUser";
        captureStdOut();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);
        }

        restoreConsoleStreams();
        String expectedQueryPart = "select * from users where username = '" + username + "'";
        assertTrue(outContent.toString().contains(expectedQueryPart), 
                "Fetch should print the executed query to console");
    }

    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        // Test that fetch prints error message when exception occurs
        String username = "exceptionUser";
        RuntimeException testException = new RuntimeException("Test database exception");
        captureStdErr();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(testException);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when an exception occurs");
        }

        restoreConsoleStreams();
        assertTrue(errContent.toString().contains("Test database exception"), 
                "Fetch should print the exception message to stderr");
    }

    @Test
    void fetch_WithNullUsername_ShouldHandleGracefully() throws Exception {
        // Test that fetch handles null username input
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(null);

            assertNull(result, "Fetch should return null for null username");
        }
    }

    @Test
    void fetch_WithEmptyUsername_ShouldReturnNull() throws Exception {
        // Test that fetch handles empty username input
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch("");

            assertNull(result, "Fetch should return null for empty username");
        }
    }

    @Test
    void fetch_ShouldReturnUserWithCorrectId() throws Exception {
        // Test that fetched user has correct id from database
        String expectedId = "12345";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(expectedId);
            when(mockResultSet.getString("username")).thenReturn("testUser");
            when(mockResultSet.getString("password")).thenReturn("hashedPassword");

            User result = User.fetch("testUser");

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedId, result.id, "Fetched user should have correct id from database");
        }
    }

    @Test
    void fetch_ShouldReturnUserWithCorrectHashedPassword() throws Exception {
        // Test that fetched user has correct hashed password from database
        String expectedPassword = "secureHashedPassword123";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn("testUser");
            when(mockResultSet.getString("password")).thenReturn(expectedPassword);

            User result = User.fetch("testUser");

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedPassword, result.hashedPassword, "Fetched user should have correct hashed password from database");
        }
    }

    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldExecuteQuery() throws Exception {
        // Test that fetch handles special characters in username (SQL injection vector)
        String specialUsername = "user'; DROP TABLE users; --";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(specialUsername);

            assertNull(result, "Fetch should return null for special characters username when no match found");
            verify(mockStatement).executeQuery(contains(specialUsername));
        }
    }

    @Test
    void fetch_ShouldHandleStatementCreationException() throws Exception {
        // Test that fetch handles exception during statement creation
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when statement creation fails");
        }
    }

    @Test
    void fetch_ShouldHandleQueryExecutionException() throws Exception {
        // Test that fetch handles exception during query execution
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when query execution fails");
        }
    }

    @Test
    void fetch_ShouldHandleResultSetException() throws Exception {
        // Test that fetch handles exception when reading from ResultSet
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenThrow(new RuntimeException("ResultSet read failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when ResultSet read fails");
        }
    }

    @Test
    void fetch_ShouldPrintExceptionClassName() throws Exception {
        // Test that fetch prints the exception class name to stderr
        captureStdErr();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new IllegalStateException("Test exception"));

            User.fetch("testUser");
        }

        restoreConsoleStreams();
        assertTrue(errContent.toString().contains("IllegalStateException"), 
                "Fetch should print exception class name to stderr");
    }

    @Test
    void fetch_QueryShouldContainDropDatabasePayload() throws Exception {
        // Test that documents the SQL injection vulnerability - query contains DROP DATABASE
        String username = "anyUser";
        captureStdOut();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);
        }

        restoreConsoleStreams();
        assertTrue(outContent.toString().contains("DROP DATABASE"), 
                "The query should contain the DROP DATABASE payload (documenting SQL injection vulnerability)");
    }
}
```
