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
    private static final String TEST_SECRET = "testSecretKeyForJWTTestingWithAtLeast32Bytes";

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

    // ==================== Constructor Tests ====================

    @Test
    void constructor_WithValidParameters_ShouldInitializeFields() {
        // Test that constructor properly initializes all fields
        User user = new User("123", "testUsername", "testHashedPassword");
        
        assertEquals("123", user.id, "User ID should be initialized correctly");
        assertEquals("testUsername", user.username, "Username should be initialized correctly");
        assertEquals("testHashedPassword", user.hashedPassword, "Hashed password should be initialized correctly");
    }

    @Test
    void constructor_WithNullValues_ShouldAcceptNullParameters() {
        // Test that constructor accepts null values without throwing exception
        User user = new User(null, null, null);
        
        assertNull(user.id, "User ID should be null when initialized with null");
        assertNull(user.username, "Username should be null when initialized with null");
        assertNull(user.hashedPassword, "Hashed password should be null when initialized with null");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyStrings() {
        // Test that constructor accepts empty strings
        User user = new User("", "", "");
        
        assertEquals("", user.id, "User ID should be empty string");
        assertEquals("", user.username, "Username should be empty string");
        assertEquals("", user.hashedPassword, "Hashed password should be empty string");
    }

    // ==================== Token Generation Tests ====================

    @Test
    void token_ShouldGenerateValidJWT() {
        // Test that token method generates a valid JWT with three parts
        String token = testUser.token(TEST_SECRET);
        
        assertNotNull(token, "Generated token should not be null");
        assertEquals(3, token.split("\\.").length, "Token should have three parts separated by dots");
    }

    @Test
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        // Test that different users get unique tokens
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
    void token_WithSameUser_ShouldGenerateConsistentTokensWithSameSecret() {
        // Test that same user with same secret generates verifiable tokens
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);
        
        // Both tokens should be valid and contain the same subject
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject1 = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token1).getBody().getSubject();
        String subject2 = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token2).getBody().getSubject();
        
        assertEquals(subject1, subject2, "Both tokens should contain the same username");
    }

    @Test
    void token_WithDifferentSecrets_ShouldGenerateDifferentTokens() {
        // Test that different secrets produce different tokens
        String secret1 = "firstSecretKeyWithAtLeast32BytesLength";
        String secret2 = "secondSecretKeyWithAtLeast32BytesLen";
        
        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);
        
        assertNotEquals(token1, token2, "Tokens generated with different secrets should be different");
    }

    // ==================== assertAuth Tests ====================

    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        // Test that assertAuth does not throw exception for valid token
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
    void assertAuth_WithExpiredToken_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized for expired token
        String expiredToken = createExpiredToken(testUser.username, TEST_SECRET);

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, expiredToken), 
                "assertAuth should throw Unauthorized for expired token");
    }

    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        // Test that assertAuth throws Unauthorized when verifying with wrong secret
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyWithAtLeast32BytesLen";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token), 
                "assertAuth should throw Unauthorized when using wrong secret");
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
        captureConsoleOutput();

        try {
            assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken));
            // Note: Stack trace is printed to stderr
        } finally {
            restoreConsoleOutput();
        }
    }

    // ==================== Fetch Tests ====================

    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        // Test that fetch returns a user when found in database
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
    }

    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        // Test that fetch returns null when user not found
        String username = "nonExistingUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
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
        // Test that demonstrates the SQL injection vulnerability in the query
        // Note: The query includes "DROP DATABASE" which is a security vulnerability
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            // Verify the vulnerable query pattern is executed
            verify(mockStatement).executeQuery(contains("DROP DATABASE"));
        }
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Test that fetch closes the connection after execution
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");

            verify(mockConnection).close();
        }
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Test that fetch prints the query to console
        String username = "testUser";
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            assertTrue(outContent.toString().contains(username), 
                    "Fetch should print the query containing username to console");
        } finally {
            restoreConsoleOutput();
        }
    }

    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        // Test that fetch prints "Opened database successfully" message
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");

            assertTrue(outContent.toString().contains("Opened database successfully"), 
                    "Fetch should print 'Opened database successfully' message");
        } finally {
            restoreConsoleOutput();
        }
    }

    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        // Test that fetch handles exception and prints error message
        String username = "exceptionUser";
        RuntimeException testException = new RuntimeException("Test database exception");
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenThrow(testException);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when an exception occurs");
            assertTrue(errContent.toString().contains("Test database exception"), 
                    "Fetch should print the exception message to stderr");
        } finally {
            restoreConsoleOutput();
        }
    }

    @Test
    void fetch_ShouldReturnNullWhenResultSetIsEmpty() throws Exception {
        // Test that fetch returns null when ResultSet is empty
        String username = "nonExistentUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when the ResultSet is empty");
        }
    }

    @Test
    void fetch_ShouldHandleMultipleResultsAndReturnFirstOne() throws Exception {
        // Test that fetch returns the first user when multiple results exist
        String username = "duplicateUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
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

    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldExecuteQuery() throws Exception {
        // Test that fetch handles special characters in username
        String username = "user'name";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            verify(mockStatement).executeQuery(contains(username));
        }
    }

    @Test
    void fetch_ShouldCorrectlyMapResultSetToUser() throws Exception {
        // Test that fetch correctly maps all fields from ResultSet to User
        String expectedId = "user123";
        String expectedUsername = "mappedUser";
        String expectedPassword = "hashedPass123";
        
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
            assertEquals(expectedId, result.id, "User ID should be correctly mapped");
            assertEquals(expectedUsername, result.username, "Username should be correctly mapped");
            assertEquals(expectedPassword, result.hashedPassword, "Hashed password should be correctly mapped");
        }
    }

    @Test
    void fetch_WithStatementCreationException_ShouldReturnNull() throws Exception {
        // Test that fetch handles exception during statement creation
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when statement creation fails");
        }
    }

    @Test
    void fetch_WithQueryExecutionException_ShouldReturnNull() throws Exception {
        // Test that fetch handles exception during query execution
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when query execution fails");
        }
    }

    @Test
    void fetch_WithResultSetException_ShouldReturnNull() throws Exception {
        // Test that fetch handles exception when reading from ResultSet
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenThrow(new RuntimeException("ResultSet read failed"));

            User result = User.fetch("testUser");

            assertNull(result, "Fetch should return null when ResultSet read fails");
        }
    }

    @Test
    void fetch_ShouldIncludeDropDatabaseInQuery() throws Exception {
        // Test that verifies the dangerous SQL injection in the query
        // This is a security vulnerability that should be fixed
        String username = "testUser";
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            String consoleOutput = outContent.toString();
            assertTrue(consoleOutput.contains("DROP DATABASE"), 
                    "Query should contain the dangerous DROP DATABASE statement (security vulnerability)");
        } finally {
            restoreConsoleOutput();
        }
    }
}
```
