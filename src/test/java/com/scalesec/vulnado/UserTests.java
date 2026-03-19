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
    private static final String TEST_SECRET = "testSecretKeyForJWTTestingMustBe32Chars";

    private ByteArrayOutputStream outContent;
    private ByteArrayOutputStream errContent;
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User("1", "testUser", "hashedPassword");
        setupConsoleCapture();
    }

    /**
     * Sets up console output capture for testing print statements
     */
    private void setupConsoleCapture() {
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
        originalOut = System.out;
        originalErr = System.err;
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    /**
     * Restores original console output streams
     */
    private void restoreConsole() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    /**
     * Creates a User instance for testing
     */
    private User createTestUser(String id, String username, String password) {
        return new User(id, username, password);
    }

    /**
     * Sets up mock database connection for fetch tests
     */
    private void setupMockDatabaseConnection() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
    }

    /**
     * Sets up mock result set with user data
     */
    private void setupMockResultSetWithUser(String userId, String username, String password) throws Exception {
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("user_id")).thenReturn(userId);
        when(mockResultSet.getString("username")).thenReturn(username);
        when(mockResultSet.getString("password")).thenReturn(password);
    }

    // ==================== Constructor Tests ====================

    @Test
    void constructor_WithValidParameters_ShouldCreateUserWithCorrectValues() {
        // Test that constructor properly initializes all fields
        User user = createTestUser("123", "testUsername", "testHashedPassword");
        
        assertEquals("123", user.id, "User id should be set correctly");
        assertEquals("testUsername", user.username, "User username should be set correctly");
        assertEquals("testHashedPassword", user.hashedPassword, "User hashedPassword should be set correctly");
    }

    @Test
    void constructor_WithNullValues_ShouldCreateUserWithNullFields() {
        // Test that constructor accepts null values
        User user = createTestUser(null, null, null);
        
        assertNull(user.id, "User id should be null");
        assertNull(user.username, "User username should be null");
        assertNull(user.hashedPassword, "User hashedPassword should be null");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldCreateUserWithEmptyFields() {
        // Test that constructor accepts empty strings
        User user = createTestUser("", "", "");
        
        assertEquals("", user.id, "User id should be empty string");
        assertEquals("", user.username, "User username should be empty string");
        assertEquals("", user.hashedPassword, "User hashedPassword should be empty string");
    }

    // ==================== Token Generation Tests ====================

    @Test
    void token_ShouldGenerateValidJWT() {
        // Test that token method generates a valid JWT format
        String token = testUser.token(TEST_SECRET);
        
        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
    }

    @Test
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        // Test that different users get different tokens
        User user1 = createTestUser("1", "user1", "password1");
        User user2 = createTestUser("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    @Test
    void token_ShouldContainCorrectUsername() {
        // Test that token contains the correct username as subject
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        
        assertEquals(testUser.username, subject, "Token should contain the correct username");
    }

    @Test
    void token_WithSameSecret_ShouldGenerateConsistentlyVerifiableTokens() {
        // Test that tokens generated with same secret can be verified
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        
        assertDoesNotThrow(() -> {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        }, "Token should be verifiable with the same secret");
    }

    @Test
    void token_WithDifferentSecrets_ShouldGenerateDifferentTokens() {
        // Test that different secrets produce different tokens
        String secret1 = "firstSecretKeyForJWTTesting12345";
        String secret2 = "secondSecretKeyForJWTTesting1234";
        
        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);
        
        assertNotEquals(token1, token2, "Tokens with different secrets should be different");
    }

    @Test
    void token_WithSpecialCharactersInUsername_ShouldGenerateValidToken() {
        // Test token generation with special characters in username
        User specialUser = createTestUser("1", "user@test.com!#$%", "password");
        String token = specialUser.token(TEST_SECRET);
        
        assertNotNull(token, "Token should be generated for username with special characters");
        assertTrue(token.split("\\.").length == 3, "Token should have valid JWT format");
    }

    // ==================== assertAuth Tests ====================

    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        // Test that valid token passes authentication
        String token = testUser.token(TEST_SECRET);
        
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token), 
            "assertAuth should not throw exception for valid token");
        restoreConsole();
    }

    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        // Test that invalid token throws Unauthorized exception
        String invalidToken = "invalidToken";
        
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken), 
            "assertAuth should throw Unauthorized for invalid token");
        restoreConsole();
    }

    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        // Test that modified token throws Unauthorized exception
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), 
            "assertAuth should throw Unauthorized for modified token");
        restoreConsole();
    }

    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        // Test that token verified with wrong secret throws Unauthorized
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "differentSecretKeyForTesting1234";
        
        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), 
            "assertAuth should throw Unauthorized when using wrong secret");
        restoreConsole();
    }

    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        // Test that empty token throws Unauthorized exception
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""), 
            "assertAuth should throw Unauthorized for empty token");
        restoreConsole();
    }

    @Test
    void assertAuth_WithNullToken_ShouldThrowException() {
        // Test that null token throws an exception
        assertThrows(Exception.class, () -> User.assertAuth(TEST_SECRET, null), 
            "assertAuth should throw exception for null token");
        restoreConsole();
    }

    @Test
    void assertAuth_ShouldPrintStackTraceOnException() {
        // Test that assertAuth prints stack trace when exception occurs
        String invalidToken = "invalidToken";

        try {
            User.assertAuth(TEST_SECRET, invalidToken);
            fail("Should have thrown Unauthorized exception");
        } catch (Unauthorized e) {
            // Expected exception
        }

        String errorOutput = errContent.toString();
        assertTrue(errorOutput.length() > 0, "assertAuth should print stack trace on exception");
        restoreConsole();
    }

    // ==================== fetch Tests ====================

    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        // Test that fetch returns user when found in database
        String username = "existingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            setupMockResultSetWithUser("1", username, "hashedPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user for existing username");
            assertEquals(username, result.username, "Fetched user should have correct username");
        }
        restoreConsole();
    }

    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        // Test that fetch returns null when user not found
        String username = "nonExistingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for non-existing username");
        }
        restoreConsole();
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
        restoreConsole();
    }

    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        // Test that fetch prints database open message
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            assertTrue(outContent.toString().contains("Opened database successfully"), 
                "Fetch should print 'Opened database successfully' message");
        }
        restoreConsole();
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Test that fetch prints the executed query
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            String consoleOutput = outContent.toString();
            assertTrue(consoleOutput.contains("select * from users where username"), 
                "Fetch should print the executed query to console");
        }
        restoreConsole();
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Test that fetch closes database connection
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
        restoreConsole();
    }

    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        // Test that fetch handles exceptions and prints error message
        String username = "exceptionUser";
        RuntimeException testException = new RuntimeException("Test database exception");
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(testException);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when an exception occurs");
            String errorOutput = errContent.toString();
            assertTrue(errorOutput.contains("Test database exception") || errorOutput.contains("RuntimeException"), 
                "Fetch should print the exception message to stderr");
        }
        restoreConsole();
    }

    @Test
    void fetch_WithSQLInjectionAttempt_ShouldExecuteQueryWithMaliciousInput() throws Exception {
        // Test that fetch handles SQL injection attempt (demonstrates vulnerability)
        String maliciousUsername = "user' OR '1'='1";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(maliciousUsername);

            verify(mockStatement).executeQuery(contains(maliciousUsername));
        }
        restoreConsole();
    }

    @Test
    void fetch_QueryContainsDropDatabaseStatement_ShouldBePresent() throws Exception {
        // Test that the SQL injection vulnerability exists in the query
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            // Verify the query contains the DROP DATABASE statement (security vulnerability)
            verify(mockStatement).executeQuery(contains("DROP DATABASE"));
        }
        restoreConsole();
    }

    @Test
    void fetch_ShouldReturnCorrectUserData() throws Exception {
        // Test that fetch returns user with correct data from database
        String expectedId = "42";
        String expectedUsername = "fetchedUser";
        String expectedPassword = "fetchedHashedPassword";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            setupMockResultSetWithUser(expectedId, expectedUsername, expectedPassword);

            User result = User.fetch(expectedUsername);

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedId, result.id, "User id should match database value");
            assertEquals(expectedUsername, result.username, "User username should match database value");
            assertEquals(expectedPassword, result.hashedPassword, "User hashedPassword should match database value");
        }
        restoreConsole();
    }

    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQuery() throws Exception {
        // Test that fetch executes query even with empty username
        String emptyUsername = "";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(emptyUsername);

            assertNull(result, "Fetch should return null for empty username when no user found");
            verify(mockStatement).executeQuery(anyString());
        }
        restoreConsole();
    }

    @Test
    void fetch_WithWhitespaceUsername_ShouldExecuteQueryWithWhitespace() throws Exception {
        // Test that fetch does not trim whitespace from username
        String whitespaceUsername = "  userWithSpaces  ";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(whitespaceUsername);

            verify(mockStatement).executeQuery(contains(whitespaceUsername));
        }
        restoreConsole();
    }

    @Test
    void fetch_WhenResultSetThrowsException_ShouldReturnNull() throws Exception {
        // Test that fetch handles ResultSet exceptions
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenThrow(new RuntimeException("ResultSet error"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when ResultSet throws exception");
        }
        restoreConsole();
    }

    @Test
    void fetch_WhenStatementCreationFails_ShouldReturnNull() throws Exception {
        // Test that fetch handles statement creation failure
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when statement creation fails");
        }
        restoreConsole();
    }

    @Test
    void fetch_WhenQueryExecutionFails_ShouldReturnNull() throws Exception {
        // Test that fetch handles query execution failure
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when query execution fails");
        }
        restoreConsole();
    }

    @Test
    void fetch_WithNullResultFromGetString_ShouldCreateUserWithNullFields() throws Exception {
        // Test that fetch handles null values from ResultSet
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(null);
            when(mockResultSet.getString("username")).thenReturn(null);
            when(mockResultSet.getString("password")).thenReturn(null);

            User result = User.fetch("testUser");

            assertNotNull(result, "Fetch should return a user even with null database values");
            assertNull(result.id, "User id should be null");
            assertNull(result.username, "User username should be null");
            assertNull(result.hashedPassword, "User hashedPassword should be null");
        }
        restoreConsole();
    }
}
```
