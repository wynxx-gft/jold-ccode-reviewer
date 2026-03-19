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
        setupStreams();
    }

    /**
     * Sets up output stream capturing for console output verification
     */
    private void setupStreams() {
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
        originalOut = System.out;
        originalErr = System.err;
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    /**
     * Restores original output streams
     */
    private void restoreStreams() {
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
     * Generates a valid JWT token for testing
     */
    private String generateValidToken(User user, String secret) {
        return user.token(secret);
    }

    // ==================== Constructor Tests ====================

    /**
     * Test: Constructor should properly initialize all fields
     */
    @Test
    void constructor_WithValidParameters_ShouldInitializeAllFields() {
        String id = "testId";
        String username = "testUsername";
        String password = "testPassword";

        User user = new User(id, username, password);

        assertEquals(id, user.id, "User id should be initialized correctly");
        assertEquals(username, user.username, "User username should be initialized correctly");
        assertEquals(password, user.hashedPassword, "User hashedPassword should be initialized correctly");
    }

    /**
     * Test: Constructor should handle null values
     */
    @Test
    void constructor_WithNullValues_ShouldAcceptNullFields() {
        User user = new User(null, null, null);

        assertNull(user.id, "User id should be null");
        assertNull(user.username, "User username should be null");
        assertNull(user.hashedPassword, "User hashedPassword should be null");
    }

    /**
     * Test: Constructor should handle empty strings
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
     * Test: token method should generate a valid JWT
     */
    @Test
    void token_ShouldGenerateValidJWT() {
        String token = testUser.token(TEST_SECRET);

        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
        restoreStreams();
    }

    /**
     * Test: token should contain correct username as subject
     */
    @Test
    void token_ShouldContainCorrectUsernameAsSubject() {
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();

        assertEquals(testUser.username, subject, "Token should contain the correct username as subject");
        restoreStreams();
    }

    /**
     * Test: Different users should generate different tokens
     */
    @Test
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        User user1 = createTestUser("1", "user1", "password1");
        User user2 = createTestUser("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
        restoreStreams();
    }

    /**
     * Test: Same user should generate consistent token structure
     */
    @Test
    void token_SameUser_ShouldGenerateValidTokenStructure() {
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        assertNotNull(token1, "First token should not be null");
        assertNotNull(token2, "Second token should not be null");
        assertEquals(3, token1.split("\\.").length, "First token should have valid JWT structure");
        assertEquals(3, token2.split("\\.").length, "Second token should have valid JWT structure");
        restoreStreams();
    }

    /**
     * Test: Token generation with special characters in username
     */
    @Test
    void token_WithSpecialCharactersInUsername_ShouldGenerateValidToken() {
        User specialUser = createTestUser("1", "user@test.com!#$%", "password");
        String token = specialUser.token(TEST_SECRET);

        assertNotNull(token, "Token should be generated for username with special characters");
        assertTrue(token.split("\\.").length == 3, "Token should have valid JWT structure");
        restoreStreams();
    }

    // ==================== AssertAuth Tests ====================

    /**
     * Test: assertAuth should not throw for valid token
     */
    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        String token = testUser.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token), "assertAuth should not throw exception for valid token");
        restoreStreams();
    }

    /**
     * Test: assertAuth should throw Unauthorized for invalid token
     */
    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        String invalidToken = "invalidToken";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken), "assertAuth should throw Unauthorized for invalid token");
        restoreStreams();
    }

    /**
     * Test: assertAuth should throw Unauthorized for modified token
     */
    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), "assertAuth should throw Unauthorized for modified token");
        restoreStreams();
    }

    /**
     * Test: assertAuth should throw Unauthorized for empty token
     */
    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""), "assertAuth should throw Unauthorized for empty token");
        restoreStreams();
    }

    /**
     * Test: assertAuth should throw Unauthorized for null token
     */
    @Test
    void assertAuth_WithNullToken_ShouldThrowUnauthorized() {
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, null), "assertAuth should throw Unauthorized for null token");
        restoreStreams();
    }

    /**
     * Test: assertAuth should throw Unauthorized for wrong secret
     */
    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForJWTTestingMustBeLongEnough";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), "assertAuth should throw Unauthorized for wrong secret");
        restoreStreams();
    }

    /**
     * Test: assertAuth should print stack trace on exception
     */
    @Test
    void assertAuth_OnException_ShouldPrintStackTrace() {
        String invalidToken = "invalidToken";

        try {
            User.assertAuth(TEST_SECRET, invalidToken);
        } catch (Unauthorized e) {
            // Expected exception
        }

        String errOutput = errContent.toString();
        assertTrue(errOutput.length() > 0, "assertAuth should print stack trace on exception");
        restoreStreams();
    }

    // ==================== Fetch Method Tests ====================

    /**
     * Test: fetch should return user when found in database
     */
    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        String username = "existingUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn(username);
            when(mockResultSet.getString("password")).thenReturn("hashedPassword");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user for existing username");
            assertEquals(username, result.username, "Fetched user should have correct username");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should return null when user not found
     */
    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        String username = "nonExistingUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null for non-existing username");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should return null when database exception occurs
     */
    @Test
    void fetch_WithDatabaseException_ShouldReturnNull() throws Exception {
        String username = "exceptionUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new RuntimeException("Database connection failed"));

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when database exception occurs");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should print "Opened database successfully" message
     */
    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            assertTrue(outContent.toString().contains("Opened database successfully"), "Fetch should print 'Opened database successfully' message");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should print the query to console
     */
    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        String username = "testUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            String output = outContent.toString();
            assertTrue(output.contains("select * from users where username = '" + username + "' limit 1"), 
                "Fetch should print the executed query to console");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should close connection after execution
     */
    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
        restoreStreams();
    }

    /**
     * Test: fetch should handle exception and print error message
     */
    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        String username = "exceptionUser";
        RuntimeException testException = new RuntimeException("Test database exception");

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(testException);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when an exception occurs");
            assertTrue(errContent.toString().contains("Test database exception"), 
                "Fetch should print the exception message to stderr");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should correctly map all user fields from ResultSet
     */
    @Test
    void fetch_ShouldCorrectlyMapAllUserFields() throws Exception {
        String expectedId = "userId123";
        String expectedUsername = "mappedUser";
        String expectedPassword = "mappedPassword";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
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
        restoreStreams();
    }

    /**
     * Test: fetch query contains SQL injection vulnerability with DROP DATABASE
     * This test documents the security vulnerability in the code
     */
    @Test
    void fetch_QueryContainsSQLInjectionVulnerability_ShouldIncludeDropDatabase() throws Exception {
        String username = "anyUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            String output = outContent.toString();
            assertTrue(output.contains("DROP DATABASE"), 
                "The query includes 'DROP DATABASE' - this is a SQL injection vulnerability");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should handle SQL injection attempt in username
     */
    @Test
    void fetch_WithSQLInjectionInUsername_ShouldExecuteQueryWithInjection() throws Exception {
        String maliciousUsername = "user' OR '1'='1";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(maliciousUsername);

            verify(mockStatement).executeQuery(contains(maliciousUsername));
        }
        restoreStreams();
    }

    /**
     * Test: fetch should return null when ResultSet is empty
     */
    @Test
    void fetch_WhenResultSetIsEmpty_ShouldReturnNull() throws Exception {
        String username = "emptyResultUser";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when the ResultSet is empty");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should handle statement creation exception
     */
    @Test
    void fetch_WhenStatementCreationFails_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when statement creation fails");
        }
        restoreStreams();
    }

    /**
     * Test: fetch should handle query execution exception
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
        restoreStreams();
    }

    /**
     * Test: fetch should handle empty username
     */
    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQuery() throws Exception {
        String emptyUsername = "";

        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(emptyUsername);

            assertNull(result, "Fetch should return null for empty username when no match found");
            verify(mockStatement).executeQuery(contains("''"));
        }
        restoreStreams();
    }

    /**
     * Test: fetch should print exception class name on error
     */
    @Test
    void fetch_OnException_ShouldPrintExceptionClassName() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(new IllegalStateException("Test exception"));

            User.fetch("testUser");

            String errOutput = errContent.toString();
            assertTrue(errOutput.contains("IllegalStateException"), 
                "Fetch should print the exception class name to stderr");
        }
        restoreStreams();
    }

    /**
     * Test: fetch always returns user in finally block (documents current behavior)
     */
    @Test
    void fetch_ShouldAlwaysReturnUserFromFinallyBlock() throws Exception {
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn("testUser");
            when(mockResultSet.getString("password")).thenReturn("password");

            User result = User.fetch("testUser");

            // The result should be the user created in the try block
            assertNotNull(result, "Fetch should return user from finally block");
        }
        restoreStreams();
    }
}
```
