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
        setupConsoleCapture();
    }

    /**
     * Sets up console output capture for testing System.out and System.err
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
     * Restores the original console streams
     */
    private void restoreConsole() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    /**
     * Creates a mock setup for database operations
     */
    private void setupMockDatabase() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
    }

    /**
     * Configures mock ResultSet to return a user
     */
    private void configureMockResultSetWithUser(String userId, String username, String password) throws Exception {
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("user_id")).thenReturn(userId);
        when(mockResultSet.getString("username")).thenReturn(username);
        when(mockResultSet.getString("password")).thenReturn(password);
    }

    // ==================== Constructor Tests ====================

    /**
     * Tests that the User constructor correctly initializes all fields
     */
    @Test
    void constructor_WithValidParameters_ShouldInitializeAllFields() {
        String expectedId = "123";
        String expectedUsername = "newUser";
        String expectedPassword = "secureHash";

        User user = new User(expectedId, expectedUsername, expectedPassword);

        assertEquals(expectedId, user.id, "User ID should be correctly initialized");
        assertEquals(expectedUsername, user.username, "Username should be correctly initialized");
        assertEquals(expectedPassword, user.hashedPassword, "Hashed password should be correctly initialized");
    }

    /**
     * Tests that the User constructor handles null values
     */
    @Test
    void constructor_WithNullValues_ShouldAcceptNulls() {
        User user = new User(null, null, null);

        assertNull(user.id, "User ID should be null when initialized with null");
        assertNull(user.username, "Username should be null when initialized with null");
        assertNull(user.hashedPassword, "Hashed password should be null when initialized with null");
    }

    /**
     * Tests that the User constructor handles empty strings
     */
    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyStrings() {
        User user = new User("", "", "");

        assertEquals("", user.id, "User ID should be empty string");
        assertEquals("", user.username, "Username should be empty string");
        assertEquals("", user.hashedPassword, "Hashed password should be empty string");
    }

    // ==================== Token Generation Tests ====================

    /**
     * Tests that token method generates a valid JWT token
     */
    @Test
    void token_ShouldGenerateValidJWT() {
        String token = testUser.token(TEST_SECRET);

        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
        restoreConsole();
    }

    /**
     * Tests that tokens are unique for different users
     */
    @Test
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
        restoreConsole();
    }

    /**
     * Tests that the token contains the correct username as subject
     */
    @Test
    void token_ShouldContainCorrectUsername() {
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();

        assertEquals(testUser.username, subject, "Token should contain the correct username");
        restoreConsole();
    }

    /**
     * Tests that the same user generates consistent tokens with same secret
     */
    @Test
    void token_SameUserSameSecret_ShouldGenerateConsistentFormat() {
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        assertNotNull(token1, "First token should not be null");
        assertNotNull(token2, "Second token should not be null");
        assertEquals(token1.split("\\.").length, token2.split("\\.").length, "Both tokens should have same structure");
        restoreConsole();
    }

    /**
     * Tests token generation with different secrets produces different tokens
     */
    @Test
    void token_WithDifferentSecrets_ShouldProduceDifferentTokens() {
        String secret1 = "firstSecretKeyForTestingPurposes123";
        String secret2 = "secondSecretKeyForTestingPurposes456";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Tokens with different secrets should be different");
        restoreConsole();
    }

    // ==================== assertAuth Tests ====================

    /**
     * Tests that assertAuth does not throw exception for valid token
     */
    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        String token = testUser.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token), "assertAuth should not throw exception for valid token");
        restoreConsole();
    }

    /**
     * Tests that assertAuth throws Unauthorized for invalid token
     */
    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        String invalidToken = "invalidToken";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken), "assertAuth should throw Unauthorized for invalid token");
        restoreConsole();
    }

    /**
     * Tests that assertAuth throws Unauthorized for modified token
     */
    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), "assertAuth should throw Unauthorized for modified token");
        restoreConsole();
    }

    /**
     * Tests that assertAuth throws Unauthorized when using wrong secret
     */
    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForTestingPurposes123";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), "assertAuth should throw Unauthorized when secret doesn't match");
        restoreConsole();
    }

    /**
     * Tests that assertAuth throws Unauthorized for null token
     */
    @Test
    void assertAuth_WithNullToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, null), "assertAuth should throw Unauthorized for null token");
        restoreConsole();
    }

    /**
     * Tests that assertAuth throws Unauthorized for empty token
     */
    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""), "assertAuth should throw Unauthorized for empty token");
        restoreConsole();
    }

    /**
     * Tests that assertAuth prints stack trace on exception
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
        restoreConsole();
    }

    // ==================== fetch Tests ====================

    /**
     * Tests that fetch returns user when user exists
     */
    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        String username = "existingUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            configureMockResultSetWithUser("1", username, "hashedPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user for existing username");
            assertEquals(username, result.username, "Fetched user should have correct username");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch returns null when user does not exist
     */
    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        String username = "nonExistingUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for non-existing username");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch returns null when database exception occurs
     */
    @Test
    void fetch_WithDatabaseException_ShouldReturnNull() throws Exception {
        String username = "exceptionUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new RuntimeException("Database connection failed"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when database exception occurs");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch executes correct SQL query
     */
    @Test
    void fetch_ShouldExecuteCorrectSQLQuery() throws Exception {
        String username = "testUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();

            User.fetch(username);

            verify(mockStatement).executeQuery("select * from users where username = '" + username + "' limit 1");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch closes connection after execution
     */
    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();

            User.fetch("testUser");

            verify(mockConnection).close();
        }
        restoreConsole();
    }

    /**
     * Tests that fetch prints "Opened database successfully" message
     */
    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();

            User.fetch("testUser");

            assertTrue(outContent.toString().contains("Opened database successfully"), "Fetch should print 'Opened database successfully' message");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch prints the query to console
     */
    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        String username = "testUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();

            User.fetch(username);

            String expectedQuery = "select * from users where username = '" + username + "' limit 1";
            assertTrue(outContent.toString().contains(expectedQuery), "Fetch should print the executed query to console");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles exception and prints error message
     */
    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        String username = "exceptionUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new RuntimeException("Test database exception"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when an exception occurs");
            assertTrue(errContent.toString().contains("Test database exception"), "Fetch should print the exception message to stderr");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch returns null when ResultSet is empty
     */
    @Test
    void fetch_ShouldReturnNullWhenResultSetIsEmpty() throws Exception {
        String username = "nonExistentUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when the ResultSet is empty");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch prints password when user is found (current behavior)
     */
    @Test
    void fetch_WhenUserFound_ShouldPrintPassword() throws Exception {
        String username = "testUser";
        String password = "testPassword";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            configureMockResultSetWithUser("1", username, password);

            User.fetch(username);

            assertTrue(outContent.toString().contains(password), "Fetch should print the password to console");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch correctly maps all user fields from ResultSet
     */
    @Test
    void fetch_ShouldCorrectlyMapAllUserFields() throws Exception {
        String expectedId = "42";
        String expectedUsername = "mappedUser";
        String expectedPassword = "mappedPassword";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            configureMockResultSetWithUser(expectedId, expectedUsername, expectedPassword);

            User result = User.fetch(expectedUsername);

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedId, result.id, "User ID should be correctly mapped");
            assertEquals(expectedUsername, result.username, "Username should be correctly mapped");
            assertEquals(expectedPassword, result.hashedPassword, "Password should be correctly mapped");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles special characters in username (SQL injection vulnerability test)
     */
    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldExecuteQuery() throws Exception {
        String maliciousUsername = "user' OR '1'='1";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(maliciousUsername);

            verify(mockStatement).executeQuery("select * from users where username = '" + maliciousUsername + "' limit 1");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles username with whitespace
     */
    @Test
    void fetch_WithWhitespaceUsername_ShouldExecuteQueryAsIs() throws Exception {
        String username = "  whitespaceUser  ";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            verify(mockStatement).executeQuery("select * from users where username = '" + username + "' limit 1");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles empty username
     */
    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQuery() throws Exception {
        String username = "";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for empty username when no match found");
            verify(mockStatement).executeQuery("select * from users where username = '' limit 1");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch only returns first result when multiple exist
     */
    @Test
    void fetch_WithMultipleResults_ShouldReturnFirstUser() throws Exception {
        String username = "duplicateUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("password1");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user");
            assertEquals("1", result.id, "Fetch should return the first user");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles null values in ResultSet
     */
    @Test
    void fetch_WithNullValuesInResultSet_ShouldCreateUserWithNulls() throws Exception {
        String username = "nullUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(null);
            when(mockResultSet.getString("username")).thenReturn(null);
            when(mockResultSet.getString("password")).thenReturn(null);

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user even with null values");
            assertNull(result.id, "User ID should be null");
            assertNull(result.username, "Username should be null");
            assertNull(result.hashedPassword, "Password should be null");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles statement creation exception
     */
    @Test
    void fetch_WhenStatementCreationFails_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when statement creation fails");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles query execution exception
     */
    @Test
    void fetch_WhenQueryExecutionFails_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when query execution fails");
        }
        restoreConsole();
    }

    /**
     * Tests that fetch handles ResultSet.next() exception
     */
    @Test
    void fetch_WhenResultSetNextFails_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabase();
            when(mockResultSet.next()).thenThrow(new RuntimeException("ResultSet navigation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when ResultSet.next() fails");
        }
        restoreConsole();
    }
}
```
