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
        
        // Capture console output for tests that need it
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

    // Helper method to create a valid JWT token
    private String createValidToken(String username, String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.builder()
                .setSubject(username)
                .signWith(key)
                .compact();
    }

    // Helper method to create an expired JWT token
    private String createExpiredToken(String username, String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();
    }

    // Helper method to setup mock database connection
    private void setupMockConnection() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
    }

    // ==================== Constructor Tests ====================

    @Test
    void constructor_WithValidParameters_ShouldSetAllFields() {
        // Test that constructor properly initializes all fields
        String id = "testId";
        String username = "testUsername";
        String hashedPassword = "testHashedPassword";

        User user = new User(id, username, hashedPassword);

        assertEquals(id, user.id, "User id should be set correctly");
        assertEquals(username, user.username, "User username should be set correctly");
        assertEquals(hashedPassword, user.hashedPassword, "User hashedPassword should be set correctly");
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
    void constructor_WithEmptyStrings_ShouldSetEmptyFields() {
        // Test that constructor accepts empty strings
        User user = new User("", "", "");

        assertEquals("", user.id, "User id should be empty string");
        assertEquals("", user.username, "User username should be empty string");
        assertEquals("", user.hashedPassword, "User hashedPassword should be empty string");
    }

    // ==================== Token Generation Tests ====================

    @Test
    void token_ShouldGenerateValidJWT() {
        // Test that token method generates a valid JWT with three parts
        String token = testUser.token(TEST_SECRET);
        
        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
    }

    @Test
    void token_ShouldContainCorrectUsername() {
        // Test that generated token contains the correct username as subject
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
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        // Test that different users get different tokens
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    @Test
    void token_WithDifferentSecrets_ShouldGenerateDifferentTokens() {
        // Test that same user with different secrets produces different tokens
        String secret1 = "firstSecretKeyForTestingPurposes123";
        String secret2 = "secondSecretKeyForTestingPurposes12";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Tokens with different secrets should be different");
    }

    @Test
    void token_WithSameSecretMultipleCalls_ShouldGenerateConsistentTokens() {
        // Test that same user with same secret produces same token structure
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        // Tokens should have same header and payload, signature may vary slightly
        String[] parts1 = token1.split("\\.");
        String[] parts2 = token2.split("\\.");

        assertEquals(parts1[0], parts2[0], "Token headers should be identical");
        assertEquals(parts1[1], parts2[1], "Token payloads should be identical");
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
        // Test that modified token is rejected
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken), 
                "assertAuth should throw Unauthorized for modified token");
    }

    @Test
    void assertAuth_WithExpiredToken_ShouldThrowUnauthorized() {
        // Test that expired token throws Unauthorized exception
        String expiredToken = createExpiredToken(testUser.username, TEST_SECRET);

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, expiredToken), 
                "assertAuth should throw Unauthorized for expired token");
    }

    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        // Test that token validated with wrong secret throws Unauthorized
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForTestingPurposes12";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), 
                "assertAuth should throw Unauthorized when validated with wrong secret");
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
        // Test that assertAuth prints stack trace when exception occurs
        String invalidToken = "invalidToken";
        captureOutput();

        try {
            assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken));
            // Stack trace should be printed to stderr
            assertTrue(errContent.toString().length() > 0, 
                    "assertAuth should print stack trace on exception");
        } finally {
            restoreOutput();
        }
    }

    // ==================== Fetch Tests ====================

    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        // Test that fetch returns user when found in database
        String username = "existingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
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
        // Test that fetch returns null when user not found
        String username = "nonExistingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
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
        // Test that demonstrates the SQL injection vulnerability in the code
        // The query includes "DROP DATABASE" which is a security concern
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            // Verify the vulnerable query format is used
            verify(mockStatement).executeQuery(contains("DROP DATABASE"));
        }
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Test that connection is closed after fetch operation
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
    }

    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        // Test that fetch prints "Opened database successfully" message
        captureOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch("testUser");

            assertTrue(outContent.toString().contains("Opened database successfully"), 
                    "Fetch should print 'Opened database successfully' message");
        } finally {
            restoreOutput();
        }
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Test that fetch prints the executed query to console
        String username = "testUser";
        captureOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            assertTrue(outContent.toString().contains("select * from users"), 
                    "Fetch should print the executed query to console");
        } finally {
            restoreOutput();
        }
    }

    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        // Test that fetch handles exceptions and prints error message
        String username = "exceptionUser";
        RuntimeException testException = new RuntimeException("Test database exception");
        captureOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(testException);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when an exception occurs");
            assertTrue(errContent.toString().contains("Test database exception"), 
                    "Fetch should print the exception message to stderr");
        } finally {
            restoreOutput();
        }
    }

    @Test
    void fetch_ShouldReturnCorrectUserFields() throws Exception {
        // Test that fetch returns user with all fields correctly populated
        String expectedId = "userId123";
        String expectedUsername = "testUsername";
        String expectedPassword = "testPassword";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn(expectedId);
            when(mockResultSet.getString("username")).thenReturn(expectedUsername);
            when(mockResultSet.getString("password")).thenReturn(expectedPassword);

            User result = User.fetch(expectedUsername);

            assertNotNull(result, "Fetch should return a user");
            assertEquals(expectedId, result.id, "User id should match database value");
            assertEquals(expectedUsername, result.username, "User username should match database value");
            assertEquals(expectedPassword, result.hashedPassword, "User hashedPassword should match database value");
        }
    }

    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldIncludeInQuery() throws Exception {
        // Test that special characters in username are included in query (SQL injection risk)
        String maliciousUsername = "user'; DROP TABLE users; --";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(maliciousUsername);

            verify(mockStatement).executeQuery(contains(maliciousUsername));
        }
    }

    @Test
    void fetch_ShouldHandleMultipleResultsAndReturnFirstOne() throws Exception {
        // Test that fetch returns only the first result when multiple exist
        String username = "duplicateUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(true, true, false);
            when(mockResultSet.getString("user_id")).thenReturn("1", "2");
            when(mockResultSet.getString("username")).thenReturn(username, username);
            when(mockResultSet.getString("password")).thenReturn("password1", "password2");

            User result = User.fetch(username);

            assertNotNull(result, "Fetch should return a user when multiple results exist");
            assertEquals("1", result.id, "Fetch should return the first user when multiple results exist");
        }
    }

    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQueryWithEmptyString() throws Exception {
        // Test that fetch handles empty username
        String emptyUsername = "";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(emptyUsername);

            assertNull(result, "Fetch should return null for empty username");
            verify(mockStatement).executeQuery(contains("''"));
        }
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
    }

    @Test
    void fetch_WhenQueryExecutionFails_ShouldReturnNull() throws Exception {
        // Test that fetch handles query execution failure
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when query execution fails");
        }
    }

    @Test
    void fetch_ShouldIncludeDropDatabaseInQuery() throws Exception {
        // Test that demonstrates the dangerous SQL in the query
        // This is a security vulnerability that should be fixed
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockConnection();
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(username);

            String expectedQueryPart = "limit 1DROP DATABASE";
            verify(mockStatement).executeQuery(argThat(query -> 
                    query.contains(expectedQueryPart)));
        }
    }
}
```
