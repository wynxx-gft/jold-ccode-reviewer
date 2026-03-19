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
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
        originalOut = System.out;
        originalErr = System.err;
    }

    // Helper method to redirect console output
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

    // Helper method to setup mock database connection
    private void setupMockDatabaseConnection() throws Exception {
        when(mockConnection.createStatement()).thenReturn(mockStatement);
    }

    // ==================== Constructor Tests ====================

    @Test
    void constructor_WithValidParameters_ShouldInitializeFields() {
        // Test that constructor properly initializes all fields
        User user = new User("testId", "testUsername", "testHashedPassword");
        
        assertEquals("testId", user.id, "User id should be initialized correctly");
        assertEquals("testUsername", user.username, "User username should be initialized correctly");
        assertEquals("testHashedPassword", user.hashedPassword, "User hashedPassword should be initialized correctly");
    }

    @Test
    void constructor_WithNullValues_ShouldAllowNullFields() {
        // Test that constructor accepts null values
        User user = new User(null, null, null);
        
        assertNull(user.id, "User id should be null when initialized with null");
        assertNull(user.username, "User username should be null when initialized with null");
        assertNull(user.hashedPassword, "User hashedPassword should be null when initialized with null");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldInitializeWithEmptyStrings() {
        // Test that constructor accepts empty strings
        User user = new User("", "", "");
        
        assertEquals("", user.id, "User id should be empty string");
        assertEquals("", user.username, "User username should be empty string");
        assertEquals("", user.hashedPassword, "User hashedPassword should be empty string");
    }

    // ==================== Token Method Tests ====================

    @Test
    void token_ShouldGenerateValidJWT() {
        // Test that token method generates a valid JWT
        String token = testUser.token(TEST_SECRET);
        
        assertNotNull(token, "Generated token should not be null");
        assertTrue(token.split("\\.").length == 3, "Token should have three parts separated by dots");
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
    void token_ShouldGenerateUniqueTokensForDifferentUsers() {
        // Test that different users generate different tokens
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    @Test
    void token_ShouldGenerateDifferentTokensWithDifferentSecrets() {
        // Test that same user generates different tokens with different secrets
        String secret1 = "secretKeyOneForTestingPurposesLong";
        String secret2 = "secretKeyTwoForTestingPurposesLong";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Tokens with different secrets should be different");
    }

    @Test
    void token_WithNullUsername_ShouldGenerateToken() {
        // Test token generation when username is null
        User userWithNullUsername = new User("1", null, "password");
        
        String token = userWithNullUsername.token(TEST_SECRET);
        
        assertNotNull(token, "Token should be generated even with null username");
    }

    // ==================== assertAuth Method Tests ====================

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
        // Test that token validated with wrong secret throws Unauthorized
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "wrongSecretKeyForTestingPurposesLong";

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
        // Test that null token throws exception
        assertThrows(Exception.class, () -> User.assertAuth(TEST_SECRET, null), 
                "assertAuth should throw exception for null token");
    }

    @Test
    void assertAuth_ShouldPrintStackTraceOnException() {
        // Test that assertAuth prints stack trace when exception occurs
        String invalidToken = "invalidToken";
        captureConsoleOutput();

        try {
            assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken));
        } finally {
            restoreConsoleOutput();
        }

        assertTrue(errContent.toString().length() > 0, 
                "assertAuth should print stack trace on exception");
    }

    @Test
    void assertAuth_WithExpiredToken_ShouldThrowUnauthorized() {
        // Test that expired token throws Unauthorized exception
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String expiredToken = Jwts.builder()
                .setSubject(testUser.username)
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 10000))
                .signWith(key)
                .compact();

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, expiredToken), 
                "assertAuth should throw Unauthorized for expired token");
    }

    // ==================== Fetch Method Tests ====================

    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        // Test that fetch returns user for existing username
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
        // Test that demonstrates the SQL injection vulnerability in the code
        // Note: The query contains ' limit 1 DROP DATABASE 1' which is a vulnerability
        String username = "testUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            // Verify the query contains the vulnerable SQL injection pattern
            verify(mockStatement).executeQuery(contains("' limit 1 DROP DATABASE 1"));
        }
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Test that fetch prints the executed query to console
        String username = "testUser";
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);
        } finally {
            restoreConsoleOutput();
        }

        String expectedQueryPart = "select * from users where username = '" + username + "'";
        assertTrue(outContent.toString().contains(expectedQueryPart), 
                "Fetch should print the executed query to console");
    }

    @Test
    void fetch_ShouldPrintDatabaseOpenMessage() throws Exception {
        // Test that fetch prints 'Opened database successfully' message
        captureConsoleOutput();
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");
        } finally {
            restoreConsoleOutput();
        }

        assertTrue(outContent.toString().contains("Opened database successfully"), 
                "Fetch should print 'Opened database successfully' message");
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Test that fetch closes the connection after execution
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch("testUser");

            verify(mockConnection).close();
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
        } finally {
            restoreConsoleOutput();
        }

        assertTrue(errContent.toString().contains("Test database exception"), 
                "Fetch should print the exception message to stderr");
    }

    @Test
    void fetch_ShouldReturnNullWhenResultSetIsEmpty() throws Exception {
        // Test that fetch returns null when ResultSet is empty
        String username = "nonExistentUser";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(username);

            assertNull(result, "Fetch should return null when the ResultSet is empty");
        }
    }

    @Test
    void fetch_WithSpecialCharactersInUsername_ShouldIncludeInQuery() throws Exception {
        // Test that special characters in username are included in query (vulnerability)
        String username = "user'; DROP TABLE users; --";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            verify(mockStatement).executeQuery(contains(username));
        }
    }

    @Test
    void fetch_ShouldCorrectlyMapDatabaseFieldsToUserObject() throws Exception {
        // Test that fetch correctly maps database fields to User object
        String expectedId = "user123";
        String expectedUsername = "mappedUser";
        String expectedPassword = "mappedHashedPassword";
        
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
            assertEquals(expectedId, result.id, "User id should be mapped correctly");
            assertEquals(expectedUsername, result.username, "User username should be mapped correctly");
            assertEquals(expectedPassword, result.hashedPassword, "User hashedPassword should be mapped correctly");
        }
    }

    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQueryWithEmptyString() throws Exception {
        // Test that fetch executes query with empty username
        String username = "";
        
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(username);

            verify(mockStatement).executeQuery(contains("username = ''"));
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
    void fetch_ShouldHandleResultSetReadException() throws Exception {
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
    void fetch_ShouldHandleConnectionCloseException() throws Exception {
        // Test that fetch still returns user even if connection close fails
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(true);
            when(mockResultSet.getString("user_id")).thenReturn("1");
            when(mockResultSet.getString("username")).thenReturn("testUser");
            when(mockResultSet.getString("password")).thenReturn("password");
            doThrow(new RuntimeException("Connection close failed")).when(mockConnection).close();

            User result = User.fetch("testUser");

            // The method should still return the user even if close fails
            // based on the finally block implementation
            assertNotNull(result, "Fetch should return user even if connection close fails");
        }
    }

    @Test
    void fetch_WithNullUsername_ShouldExecuteQueryWithNullString() throws Exception {
        // Test that fetch handles null username
        try (MockedStatic<Postgres> mockedPostgres = mockStatic(Postgres.class)) {
            mockedPostgres.when(Postgres::connection).thenReturn(mockConnection);
            setupMockDatabaseConnection();
            when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

            User.fetch(null);

            verify(mockStatement).executeQuery(contains("username = 'null'"));
        }
    }
}
```
