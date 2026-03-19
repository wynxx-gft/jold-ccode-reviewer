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
        
        // Capture System.out and System.err
        originalOut = System.out;
        originalErr = System.err;
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
    }

    // Helper method to set up console capture
    private void captureConsoleOutput() {
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    // Helper method to restore console output
    private void restoreConsoleOutput() {
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

    // Helper method to set up mock database connection
    private void setupMockDatabaseConnection() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
    }

    // ==================== Constructor Tests ====================

    @Test
    void constructor_ShouldInitializeAllFields() {
        // Test that constructor properly initializes all fields
        String id = "testId";
        String username = "testUsername";
        String hashedPassword = "testHashedPassword";

        User user = new User(id, username, hashedPassword);

        assertEquals(id, user.id, "User id should be initialized correctly");
        assertEquals(username, user.username, "User username should be initialized correctly");
        assertEquals(hashedPassword, user.hashedPassword, "User hashedPassword should be initialized correctly");
    }

    @Test
    void constructor_WithNullValues_ShouldAcceptNullFields() {
        // Test that constructor accepts null values
        User user = new User(null, null, null);

        assertNull(user.id, "User id should be null when initialized with null");
        assertNull(user.username, "User username should be null when initialized with null");
        assertNull(user.hashedPassword, "User hashedPassword should be null when initialized with null");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyStrings() {
        // Test that constructor accepts empty strings
        User user = new User("", "", "");

        assertEquals("", user.id, "User id should be empty string");
        assertEquals("", user.username, "User username should be empty string");
        assertEquals("", user.hashedPassword, "User hashedPassword should be empty string");
    }

    // ==================== Token Generation Tests ====================

    @Test
    void token_ShouldGenerateValidJWT() {
        // Test that token method generates a valid JWT
        String token = testUser.token(TEST_SECRET);
        
        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
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
        // Test that token contains the correct username as subject
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        
        assertEquals(testUser.username, subject, "Token should contain the correct username");
    }

    @Test
    void token_WithDifferentSecrets_ShouldGenerateDifferentTokens() {
        // Test that same user with different secrets generates different tokens
        String secret1 = "secretKeyOneForTestingPurposesLongEnough";
        String secret2 = "secretKeyTwoForTestingPurposesLongEnough";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Tokens with different secrets should be different");
    }

    @Test
    void token_ShouldGenerateConsistentTokenStructure() {
        // Test that token structure is consistent
        String token = testUser.token(TEST_SECRET);
        String[] parts = token.split("\\.");

        assertEquals(3, parts.length, "JWT should have exactly 3 parts: header, payload, signature");
        assertTrue(parts[0].length() > 0, "Header part should not be empty");
        assertTrue(parts[1].length() > 0, "Payload part should not be empty");
        assertTrue(parts[2].length() > 0, "Signature part should not be empty");
    }

    // ==================== assertAuth Tests ====================

    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        // Test that valid token passes authentication
        String token = testUser.token(TEST_SECRET);
        
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token), 
                "assertAuth should not throw exception for valid token");
    }

    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        // Test that invalid token throws Unauthorized exception
        String invalidToken = "invalidToken";
        
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken), 
                "assertAuth should throw Unauthorized for invalid token");
    }

    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        // Test that modified token throws Unauthorized exception
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), 
                "assertAuth should throw Unauthorized for modified token");
    }

    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        // Test that token verified with wrong secret throws Unauthorized
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForTestingPurposesLongEnough";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), 
                "assertAuth should throw Unauthorized when using wrong secret");
    }

    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        // Test that empty token throws Unauthorized exception
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""), 
                "assertAuth should throw Unauthorized for empty token");
    }

    @Test
    void assertAuth_WithNullToken_ShouldThrowException() {
        // Test that null token throws an exception
        assertThrows(Exception.class, () -> User.assertAuth(TEST_SECRET, null), 
                "assertAuth should throw exception for null token");
    }

    @Test
    void assertAuth_ShouldPrintStackTraceOnException() {
        // Test that assertAuth prints stack trace on exception
        captureConsoleOutput();
        
        try {
            User.assertAuth(TEST_SECRET, "invalidToken");
        } catch (Unauthorized e) {
            // Expected exception
        }
        
        restoreConsoleOutput();
        
        assertTrue(errContent.toString().length() > 0, 
                "assertAuth should print stack trace to stderr on exception");
    }

    @Test
    void assertAuth_WithMalformedToken_ShouldThrowUnauthorized() {
        // Test that malformed token throws Unauthorized
        String malformedToken = "not.a.valid.jwt.token";
        
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, malformedToken), 
                "assertAuth should throw Unauthorized for malformed token");
    }

    // ==================== fetch Tests ====================

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
        // Test that verifies the SQL injection vulnerability in the query
        // Note: This test documents the security vulnerability in the code
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            // Verify the vulnerable query construction with DROP DATABASE
            String expectedQuery = "select * from users where username = '" + username + "' limit 1DROP DATABASE 1";
            verify(mockStatement).executeQuery(expectedQuery);
        }
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Test that connection is closed after fetch
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
        // Test that fetch prints database opened message
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");
        }
        
        restoreConsoleOutput();
        
        assertTrue(outContent.toString().contains("Opened database successfully"), 
                "Fetch should print 'Opened database successfully' message");
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Test that fetch prints the query to console
        String username = "testUser";
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);
        }
        
        restoreConsoleOutput();
        
        String expectedQuery = "select * from users where username = '" + username + "' limit 1DROP DATABASE 1";
        assertTrue(outContent.toString().contains(expectedQuery), 
                "Fetch should print the executed query to console");
    }

    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        // Test that fetch handles exceptions and prints error messages
        captureConsoleOutput();
        RuntimeException testException = new RuntimeException("Test database exception");
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(testException);

            User result = User.fetch("exceptionUser");

            assertNull(result, "Fetch should return null when an exception occurs");
        }
        
        restoreConsoleOutput();
        
        assertTrue(errContent.toString().contains("Test database exception"), 
                "Fetch should print the exception message to stderr");
    }

    @Test
    void fetch_ShouldReturnNullWhenResultSetIsEmpty() throws Exception {
        // Test that fetch returns null when ResultSet is empty
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch("nonExistentUser");

            assertNull(result, "Fetch should return null when the ResultSet is empty");
        }
    }

    @Test
    void fetch_ShouldCorrectlyMapResultSetToUser() throws Exception {
        // Test that fetch correctly maps ResultSet fields to User object
        String expectedId = "userId123";
        String expectedUsername = "mappedUser";
        String expectedPassword = "mappedPassword";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(expectedId);
            when(mockResultSet.getString("username")).thenReturn(expectedUsername);
            when(mockResultSet.getString("password")).thenReturn(expectedPassword);

            User result = User.fetch(expectedUsername);

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedId, result.id, "User id should match ResultSet value");
            assertEquals(expectedUsername, result.username, "User username should match ResultSet value");
            assertEquals(expectedPassword, result.hashedPassword, "User hashedPassword should match ResultSet value");
        }
    }

    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldExecuteQuery() throws Exception {
        // Test fetch with special characters in username (demonstrates SQL injection risk)
        String specialUsername = "user'; DROP TABLE users; --";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(specialUsername);

            verify(mockStatement).executeQuery(contains(specialUsername));
        }
    }

    @Test
    void fetch_ShouldCreateStatementFromConnection() throws Exception {
        // Test that fetch creates a statement from the connection
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");

            verify(mockConnection).createStatement();
        }
    }

    @Test
    void fetch_WithNullUsername_ShouldHandleGracefully() throws Exception {
        // Test that fetch handles null username
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
    void fetch_WithEmptyUsername_ShouldExecuteQuery() throws Exception {
        // Test that fetch executes query with empty username
        String emptyUsername = "";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(emptyUsername);

            assertNull(result, "Fetch should return null for empty username when no user found");
            verify(mockStatement).executeQuery(contains("''"));
        }
    }

    @Test
    void fetch_ShouldReturnUserInFinallyBlock() throws Exception {
        // Test that user is returned from finally block
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn("testUser");
            when(mockResultSet.getString("password")).thenReturn("password");

            User result = User.fetch("testUser");

            assertNotNull(result, "Fetch should return user from finally block");
        }
    }

    @Test
    void fetch_WithConnectionCloseException_ShouldStillReturnUser() throws Exception {
        // Test that user is returned even if connection close throws exception
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn("testUser");
            when(mockResultSet.getString("password")).thenReturn("password");
            doThrow(new RuntimeException("Close failed")).when(mockConnection).close();

            User result = User.fetch("testUser");

            // The method should still return the user despite close exception
            assertNotNull(result, "Fetch should return user even if connection close fails");
        }
    }
}
```
