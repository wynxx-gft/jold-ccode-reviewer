Looking at the provided code and existing tests, I can see the existing tests are quite comprehensive. I'll analyze what's covered and add tests for any gaps or edge cases not yet addressed.

After careful review, the existing tests cover constructor, token(), assertAuth(), and fetch() extensively. I'll add additional tests for uncovered scenarios and edge cases.

```java
package com.scalesec.vulnado;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
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
    private static final String TEST_SECRET = "testSecretKeyForJWTTestingLongEnoughForHMAC";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User("1", "testUser", "hashedPassword");
    }

    // Helper method to set up mock database connection
    private void setupMockConnection() throws Exception {
        when(Postgres.connection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
    }

    // Helper method to set up mock result set with a user record
    private void setupMockResultSetWithUser(String userId, String username, String password) throws Exception {
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("user_id")).thenReturn(userId);
        when(mockResultSet.getString("username")).thenReturn(username);
        when(mockResultSet.getString("password")).thenReturn(password);
    }

    // Helper to capture System.out
    private ByteArrayOutputStream captureSystemOut() {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        return outContent;
    }

    // Helper to capture System.err
    private ByteArrayOutputStream captureSystemErr() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errContent));
        return errContent;
    }

    // Helper to restore standard streams
    private void restoreStreams() {
        System.setOut(System.out);
        System.setErr(System.err);
    }

    // --- Constructor tests ---

    @Test
    void constructor_InitializeFields_ShouldSetIdUsernameAndHashedPassword() {
        // Verify that the constructor correctly assigns all fields
        User user = new User("42", "alice", "hashed123");
        assertEquals("42", user.id, "Constructor should set the id field");
        assertEquals("alice", user.username, "Constructor should set the username field");
        assertEquals("hashed123", user.hashedPassword, "Constructor should set the hashedPassword field");
    }

    @Test
    void constructor_WithNullValues_ShouldAcceptNulls() {
        // Verify constructor does not throw when null values are passed
        User user = new User(null, null, null);
        assertNull(user.id, "Constructor should allow null id");
        assertNull(user.username, "Constructor should allow null username");
        assertNull(user.hashedPassword, "Constructor should allow null hashedPassword");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyStrings() {
        // Verify constructor handles empty strings
        User user = new User("", "", "");
        assertEquals("", user.id, "Constructor should accept empty string for id");
        assertEquals("", user.username, "Constructor should accept empty string for username");
        assertEquals("", user.hashedPassword, "Constructor should accept empty string for hashedPassword");
    }

    @Test
    void constructor_WithWhitespaceValues_ShouldPreserveWhitespace() {
        // Verify constructor preserves whitespace in fields
        User user = new User("  ", " user ", " pass ");
        assertEquals("  ", user.id, "Constructor should preserve whitespace in id");
        assertEquals(" user ", user.username, "Constructor should preserve whitespace in username");
        assertEquals(" pass ", user.hashedPassword, "Constructor should preserve whitespace in hashedPassword");
    }

    @Test
    void constructor_FieldsArePublic_ShouldBeDirectlyAccessible() {
        // Verify fields are public and can be modified directly
        User user = new User("1", "original", "origPass");
        user.id = "2";
        user.username = "modified";
        user.hashedPassword = "newPass";
        assertEquals("2", user.id, "Public field id should be modifiable");
        assertEquals("modified", user.username, "Public field username should be modifiable");
        assertEquals("newPass", user.hashedPassword, "Public field hashedPassword should be modifiable");
    }

    // --- token() tests ---

    @Test
    void token_GenerateJWT_ShouldReturnNonNullToken() {
        // Verify that a token is generated and is not null
        String token = testUser.token(TEST_SECRET);
        assertNotNull(token, "Generated token should not be null");
    }

    @Test
    void token_GenerateJWT_ShouldReturnThreePartToken() {
        // JWT tokens have three parts separated by dots
        String token = testUser.token(TEST_SECRET);
        assertEquals(3, token.split("\\.").length, "Token should have three parts separated by dots");
    }

    @Test
    void token_GenerateJWT_ShouldContainCorrectSubject() {
        // Verify the token subject matches the username
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals(testUser.username, subject, "Token subject should match the username");
    }

    @Test
    void token_DifferentUsers_ShouldGenerateUniqueTokens() {
        // Different users should produce different tokens
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    @Test
    void token_SameUserCalledTwice_ShouldProduceConsistentlyVerifiableTokens() {
        // Both tokens from the same user should be verifiable with the same secret
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);

        assertNotNull(token1, "First token should not be null");
        assertNotNull(token2, "Second token should not be null");

        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        assertDoesNotThrow(() -> Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token1),
                "First token should be valid");
        assertDoesNotThrow(() -> Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token2),
                "Second token should be valid");
    }

    @Test
    void token_WithDifferentSecrets_ShouldProduceDifferentTokens() {
        // Tokens signed with different secrets should differ
        String secret1 = "firstSecretKeyThatIsLongEnoughForHMAC";
        String secret2 = "secondSecretKeyThatIsLongEnoughForHMAC";

        String token1 = testUser.token(secret1);
        String token2 = testUser.token(secret2);

        assertNotEquals(token1, token2, "Tokens signed with different secrets should differ");
    }

    @Test
    void token_WithSpecialCharactersInUsername_ShouldGenerateValidToken() {
        // Verify token generation works with special characters in username
        User specialUser = new User("3", "user@domain.com!#$%", "pass");
        String token = specialUser.token(TEST_SECRET);
        assertNotNull(token, "Token should be generated for username with special characters");

        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals("user@domain.com!#$%", subject, "Token subject should preserve special characters");
    }

    @Test
    void token_WithEmptyUsername_ShouldGenerateValidToken() {
        // Verify token generation works with an empty username
        User emptyUser = new User("4", "", "pass");
        String token = emptyUser.token(TEST_SECRET);
        assertNotNull(token, "Token should be generated for empty username");

        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals("", subject, "Token subject should be empty string for empty username");
    }

    @Test
    void token_WithUnicodeUsername_ShouldGenerateValidToken() {
        // Verify token generation works with unicode characters in username
        User unicodeUser = new User("5", "用户名テスト🚀", "pass");
        String token = unicodeUser.token(TEST_SECRET);
        assertNotNull(token, "Token should be generated for unicode username");

        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals("用户名テスト🚀", subject, "Token subject should preserve unicode characters including emoji");
    }

    @Test
    void token_WithNullUsername_ShouldGenerateTokenWithNullSubject() {
        // Verify token generation behavior with null username
        User nullUser = new User("6", null, "pass");
        String token = nullUser.token(TEST_SECRET);
        assertNotNull(token, "Token should be generated even with null username");

        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertNull(subject, "Token subject should be null for null username");
    }

    @Test
    void token_WithVeryLongUsername_ShouldGenerateValidToken() {
        // Verify token generation works with a very long username
        String longUsername = "a".repeat(5000);
        User longUser = new User("7", longUsername, "pass");
        String token = longUser.token(TEST_SECRET);
        assertNotNull(token, "Token should be generated for very long username");

        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals(longUsername, subject, "Token subject should preserve very long username");
    }

    @Test
    void token_ReturnedToken_ShouldNotContainExpirationByDefault() {
        // Verify the token does not have an expiration claim (code does not set one)
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        java.util.Date expiration = Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getExpiration();
        assertNull(expiration, "Token should not have an expiration date by default");
    }

    @Test
    void token_ReturnedToken_ShouldNotContainIssuedAtByDefault() {
        // Verify the token does not have an issuedAt claim (code does not set one)
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        java.util.Date issuedAt = Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getIssuedAt();
        assertNull(issuedAt, "Token should not have an issuedAt date by default");
    }

    @Test
    void token_ReturnedToken_ShouldBeNonEmpty() {
        // Verify the generated token string is not empty
        String token = testUser.token(TEST_SECRET);
        assertFalse(token.isEmpty(), "Generated token should not be an empty string");
    }

    // --- assertAuth() tests ---

    @Test
    void assertAuth_WithValidToken_ShouldNotThrowException() {
        // Valid token should pass authentication
        String token = testUser.token(TEST_SECRET);
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token),
                "assertAuth should not throw exception for valid token");
    }

    @Test
    void assertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        // Completely invalid token string should throw Unauthorized
        String invalidToken = "invalidToken";
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken),
                "assertAuth should throw Unauthorized for invalid token");
    }

    @Test
    void assertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        // A tampered token should fail authentication
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken),
                "assertAuth should throw Unauthorized for modified token");
    }

    @Test
    void assertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        // Token verified with a different secret should fail
        String token = testUser.token(TEST_SECRET);
        String wrongSecret = "completelyDifferentSecretKeyForHMAC!";

        assertThrows(Unauthorized.class, () -> User.assertAuth(wrongSecret, token),
                "assertAuth should throw Unauthorized when secret does not match");
    }

    @Test
    void assertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        // Empty string token should throw Unauthorized
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""),
                "assertAuth should throw Unauthorized for empty token");
    }

    @Test
    void assertAuth_WithNullToken_ShouldThrowUnauthorized() {
        // Null token should throw Unauthorized
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, null),
                "assertAuth should throw Unauthorized for null token");
    }

    @Test
    void assertAuth_WithExpiredToken_ShouldThrowUnauthorized() {
        // Expired token should fail authentication
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String expiredToken = Jwts.builder()
                .setSubject(testUser.username)
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, expiredToken),
                "assertAuth should throw Unauthorized for expired token");
    }

    @Test
    void assertAuth_WithMalformedJWT_ShouldThrowUnauthorized() {
        // A malformed JWT with correct structure but invalid content should fail
        String malformedToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalidsignature";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, malformedToken),
                "assertAuth should throw Unauthorized for malformed JWT");
    }

    @Test
    void assertAuth_ShouldPrintStackTraceOnException() {
        // Verify that stack trace is printed to stderr on authentication failure
        String invalidToken = "invalidToken";
        ByteArrayOutputStream errContent = captureSystemErr();

        try {
            assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, invalidToken));
            assertTrue(errContent.toString().length() > 0,
                    "assertAuth should print error information on exception");
        } finally {
            restoreStreams();
        }
    }

    @Test
    void assertAuth_WithTokenFromDifferentAlgorithm_ShouldThrowUnauthorized() {
        // Verify that a token signed with a different key size/algorithm fails
        SecretKey differentKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS384);
        String tokenWithDifferentAlg = Jwts.builder()
                .setSubject("testUser")
                .signWith(differentKey)
                .compact();

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, tokenWithDifferentAlg),
                "assertAuth should throw Unauthorized for token signed with different algorithm key");
    }

    @Test
    void assertAuth_WithTokenMissingSignature_ShouldThrowUnauthorized() {
        // A JWT with no signature part (unsigned) should fail
        String unsignedToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0VXNlciJ9.";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, unsignedToken),
                "assertAuth should throw Unauthorized for unsigned token");
    }

    @Test
    void assertAuth_UnauthorizedException_ShouldContainMessage() {
        // Verify the Unauthorized exception contains a meaningful message
        String invalidToken = "not.a.valid.token";

        Unauthorized exception = assertThrows(Unauthorized.class,
                () -> User.assertAuth(TEST_SECRET, invalidToken),
                "assertAuth should throw Unauthorized for invalid token format");
        assertNotNull(exception.getMessage(), "Unauthorized exception should contain a message");
        assertFalse(exception.getMessage().isEmpty(), "Unauthorized exception message should not be empty");
    }

    @Test
    void assertAuth_WithTokenHavingExtraSegments_ShouldThrowUnauthorized() {
        // Token with extra dot-separated segments should fail
        String extraSegmentToken = "aaa.bbb.ccc.ddd";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, extraSegmentToken),
                "assertAuth should throw Unauthorized for token with extra segments");
    }

    @Test
    void assertAuth_WithWhitespaceToken_ShouldThrowUnauthorized() {
        // Whitespace-only token should throw Unauthorized
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, "   "),
                "assertAuth should throw Unauthorized for whitespace-only token");
    }

    @Test
    void assertAuth_ValidTokenMultipleTimes_ShouldSucceedEveryTime() {
        // Verify that the same valid token can be verified multiple times
        String token = testUser.token(TEST_SECRET);
        for (int i = 0; i < 5; i++) {
            final int iteration = i;
            assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token),
                    "assertAuth should succeed on iteration " + iteration);
        }
    }

    // --- fetch() tests ---

    @Test
    void fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        // Verify fetch returns a user when one exists in the database
        String username = "existingUser";
        setupMockConnection();
        setupMockResultSetWithUser("1", username, "hashedPassword");

        User result = User.fetch(username);

        assertNotNull(result, "Fetch should return a user for existing username");
        assertEquals(username, result.username, "Fetched user should have correct username");
    }

    @Test
    void fetch_WithExistingUser_ShouldReturnCorrectId() throws Exception {
        // Verify the returned user has the correct ID
        setupMockConnection();
        setupMockResultSetWithUser("42", "someUser", "somePass");

        User result = User.fetch("someUser");

        assertNotNull(result, "Fetch should return a user");
        assertEquals("42", result.id, "Fetched user should have correct id");
    }

    @Test
    void fetch_WithExistingUser_ShouldReturnCorrectPassword() throws Exception {
        // Verify the returned user has the correct hashed password
        setupMockConnection();
        setupMockResultSetWithUser("1", "user1", "secretHash");

        User result = User.fetch("user1");

        assertNotNull(result, "Fetch should return a user");
        assertEquals("secretHash", result.hashedPassword, "Fetched user should have correct hashedPassword");
    }

    @Test
    void fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        // Non-existing user should return null
        String username = "nonExistingUser";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch(username);

        assertNull(result, "Fetch should return null for non-existing username");
    }

    @Test
    void fetch_WithDatabaseException_ShouldReturnNull() throws Exception {
        // Database connection failure should result in null return
        String username = "exceptionUser";
        when(Postgres.connection()).thenThrow(new RuntimeException("Database connection failed"));

        User result = User.fetch(username);

        assertNull(result, "Fetch should return null when database exception occurs");
    }

    @Test
    void fetch_ShouldExecuteQueryContainingUsername() throws Exception {
        // Verify the SQL query includes the username
        String username = "testUser";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch(username);

        verify(mockStatement).executeQuery(contains(username));
    }

    @Test
    void fetch_ShouldCloseConnectionAfterExecution() throws Exception {
        // Verify the database connection is closed after fetch
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockConnection).close();
    }

    @Test
    void fetch_ShouldPrintOpenedDatabaseMessage() throws Exception {
        // Verify "Opened database successfully" is printed to stdout
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        ByteArrayOutputStream outContent = captureSystemOut();
        try {
            User.fetch("testUser");
            assertTrue(outContent.toString().contains("Opened database successfully"),
                    "Fetch should print 'Opened database successfully' message");
        } finally {
            restoreStreams();
        }
    }

    @Test
    void fetch_ShouldPrintQueryToConsole() throws Exception {
        // Verify the executed query is printed to stdout
        String username = "testUser";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        ByteArrayOutputStream outContent = captureSystemOut();
        try {
            User.fetch(username);
            assertTrue(outContent.toString().contains(username),
                    "Fetch should print the query containing the username to console");
        } finally {
            restoreStreams();
        }
    }

    @Test
    void fetch_ShouldHandleExceptionAndPrintErrorMessage() throws Exception {
        // Verify error message is printed to stderr on exception
        String username = "exceptionUser";
        RuntimeException testException = new RuntimeException("Test database exception");
        when(Postgres.connection()).thenThrow(testException);

        ByteArrayOutputStream errContent = captureSystemErr();
        try {
            User result = User.fetch(username);
            assertNull(result, "Fetch should return null when an exception occurs");
            assertTrue(errContent.toString().contains("Test database exception"),
                    "Fetch should print the exception message to stderr");
        } finally {
            restoreStreams();
        }
    }

    @Test
    void fetch_WithSQLInjectionAttempt_ShouldExecuteQueryAsIs() throws Exception {
        // The code is vulnerable to SQL injection; verify query is built with raw input
        String maliciousUsername = "user' OR '1'='1";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch(maliciousUsername);

        verify(mockStatement).executeQuery(contains(maliciousUsername));
    }

    @Test
    void fetch_ShouldHandleMultipleResultsAndReturnFirstOne() throws Exception {
        // When multiple rows exist, only the first should be returned
        String username = "duplicateUser";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(true, true, false);
        when(mockResultSet.getString("user_id")).thenReturn("1", "2");
        when(mockResultSet.getString("username")).thenReturn(username, username);
        when(mockResultSet.getString("password")).thenReturn("password1", "password2");

        User result = User.fetch(username);

        assertNotNull(result, "Fetch should return a user when multiple results exist");
        assertEquals("1", result.id, "Fetch should return the first user when multiple results exist");
    }

    @Test
    void fetch_WithEmptyUsername_ShouldExecuteQueryWithEmptyString() throws Exception {
        // Verify fetch handles empty username string
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch("");

        assertNull(result, "Fetch should return null for empty username");
        verify(mockStatement).executeQuery(contains("''"));
    }

    @Test
    void fetch_WithStatementCreationFailure_ShouldReturnNull() throws Exception {
        // Verify graceful handling when statement creation fails
        when(Postgres.connection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenThrow(new java.sql.SQLException("Statement creation failed"));

        User result = User.fetch("anyUser");

        assertNull(result, "Fetch should return null when statement creation fails");
    }

    @Test
    void fetch_WithResultSetException_ShouldReturnNull() throws Exception {
        // Verify graceful handling when ResultSet throws exception
        setupMockConnection();
        when(mockResultSet.next()).thenThrow(new java.sql.SQLException("ResultSet error"));

        User result = User.fetch("anyUser");

        assertNull(result, "Fetch should return null when ResultSet throws exception");
    }

    @Test
    void fetch_QueryShouldContainDeleteInjection_ShouldIncludeDangerousPayload() throws Exception {
        // The source code contains an injected DELETE statement in the query string
        // This test verifies the query includes the DELETE payload
        String username = "testUser";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch(username);

        verify(mockStatement).executeQuery(contains("DELETE"));
    }

    @Test
    void fetch_WithLongUsername_ShouldPassItToQuery() throws Exception {
        // Verify fetch can handle long usernames
        String longUsername = "a".repeat(1000);
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch(longUsername);

        assertNull(result, "Fetch should return null for non-existing long username");
        verify(mockStatement).executeQuery(contains(longUsername));
    }

    @Test
    void fetch_WithUnicodeUsername_ShouldPassItToQuery() throws Exception {
        // Verify fetch handles unicode characters in username
        String unicodeUsername = "用户名テスト";
        setupMockConnection();
        setupMockResultSetWithUser("99", unicodeUsername, "pass");

        User result = User.fetch(unicodeUsername);

        assertNotNull(result, "Fetch should return a user for unicode username");
        assertEquals(unicodeUsername, result.username, "Username should preserve unicode characters");
    }

    @Test
    void fetch_WhenConnectionCloseThrows_ShouldStillReturnUser() throws Exception {
        // Even if connection.close() throws, the user should be returned from finally block
        setupMockConnection();
        setupMockResultSetWithUser("1", "testUser", "pass");
        doThrow(new java.sql.SQLException("Close failed")).when(mockConnection).close();

        User result = User.fetch("testUser");

        assertNotNull(result, "Fetch should still return user even if connection close fails");
        assertEquals("testUser", result.username, "Returned user should have correct username");
    }

    @Test
    void fetch_WhenQueryExecutionFails_ShouldReturnNull() throws Exception {
        // Verify null is returned when query execution throws
        when(Postgres.connection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenThrow(new java.sql.SQLException("Query failed"));

        User result = User.fetch("anyUser");

        assertNull(result, "Fetch should return null when query execution fails");
    }

    // --- Additional fetch() tests for increased coverage ---

    @Test
    void fetch_QueryShouldContainSelectFromUsers_ShouldBuildCorrectSQL() throws Exception {
        // Verify the query contains the expected SQL structure
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockStatement).executeQuery(contains("select * from users where username"));
    }

    @Test
    void fetch_QueryShouldContainLimit1_ShouldLimitResults() throws Exception {
        // Verify the query contains LIMIT 1 clause
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockStatement).executeQuery(contains("limit 1"));
    }

    @Test
    void fetch_ShouldPrintErrorClassNameOnException() throws Exception {
        // Verify the error class name is printed to stderr
        java.sql.SQLException sqlException = new java.sql.SQLException("DB Error");
        when(Postgres.connection()).thenThrow(sqlException);

        ByteArrayOutputStream errContent = captureSystemErr();
        try {
            User.fetch("anyUser");
            assertTrue(errContent.toString().contains("SQLException"),
                    "Fetch should print exception class name to stderr");
        } finally {
            restoreStreams();
        }
    }

    @Test
    void fetch_WithSpecialSQLCharacters_ShouldPassThemToQuery() throws Exception {
        // Verify that special SQL characters like semicolons and dashes pass through
        String dangerousUsername = "'; DROP TABLE users; --";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch(dangerousUsername);

        verify(mockStatement).executeQuery(contains("DROP TABLE"));
    }

    @Test
    void fetch_WithNewlineInUsername_ShouldPassItToQuery() throws Exception {
        // Verify that newline characters in username are passed to the query
        String usernameWithNewline = "user\nname";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch(usernameWithNewline);

        verify(mockStatement).executeQuery(contains(usernameWithNewline));
    }

    @Test
    void fetch_ReturnsUserFromFinallyBlock_ShouldReturnNullWhenNoResultFound() throws Exception {
        // Verify that the finally block returns null user when no result is found
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch("nonexistent");

        assertNull(result, "Fetch should return null from finally block when no user found");
    }

    @Test
    void fetch_WithExistingUser_ShouldReturnCompleteUserObject() throws Exception {
        // Verify all three fields of the returned user object are populated
        setupMockConnection();
        setupMockResultSetWithUser("100", "completeUser", "hashedPwd123");

        User result = User.fetch("completeUser");

        assertNotNull(result, "Fetch should return a non-null user");
        assertAll("All user fields should be correctly populated",
                () -> assertEquals("100", result.id, "User id should match"),
                () -> assertEquals("completeUser", result.username, "User username should match"),
                () -> assertEquals("hashedPwd123", result.hashedPassword, "User hashedPassword should match")
        );
    }

    @Test
    void fetch_QueryContainsDeleteFromUsers_ShouldContainMaliciousPayload() throws Exception {
        // Verify the specific DELETE FROM USERS payload embedded in the source code
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("anyUser");

        verify(mockStatement).executeQuery(contains("DELETE  FROM USERS"));
    }

    @Test
    void fetch_ConnectionCloseCalledAfterSuccess_ShouldCloseConnectionOnSuccessfulFetch() throws Exception {
        // Verify connection is closed even on successful user retrieval
        setupMockConnection();
        setupMockResultSetWithUser("1", "user", "pass");

        User.fetch("user");

        verify(mockConnection, times(1)).close();
    }

    @Test
    void fetch_StatementCreated_ShouldCreateExactlyOneStatement() throws Exception {
        // Verify exactly one statement is created per fetch call
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockConnection, times(1)).createStatement();
    }

    @Test
    void fetch_QueryExecuted_ShouldExecuteExactlyOneQuery() throws Exception {
        // Verify exactly one query is executed per fetch call
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockStatement, times(1)).executeQuery(anyString());
    }

    @Test
    void fetch_ResultSetIterated_ShouldCallNextOnResultSet() throws Exception {
        // Verify that next() is called on the ResultSet
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockResultSet, atLeastOnce()).next();
    }

    @Test
    void fetch_WithNullConnectionReturn_ShouldThrowAndReturnNull() throws Exception {
        // Verify behavior when Postgres.connection() returns null
        when(Postgres.connection()).thenReturn(null);

        User result = User.fetch("testUser");

        assertNull(result, "Fetch should return null when connection is null and NPE occurs");
    }

    // --- Integration-style tests: token + assertAuth ---

    @Test
    void tokenAndAssertAuth_RoundTrip_ShouldValidateGeneratedToken() {
        // End-to-end: generate token then validate it
        User user = new User("10", "roundTripUser", "pass");
        String token = user.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token),
                "assertAuth should validate a token generated by the same user and secret");
    }

    @Test
    void tokenAndAssertAuth_DifferentUserTokens_ShouldBothValidateWithSameSecret() {
        // Both users' tokens should validate with the same secret
        User userA = new User("11", "userA", "passA");
        User userB = new User("12", "userB", "passB");

        String tokenA = userA.token(TEST_SECRET);
        String tokenB = userB.token(TEST_SECRET);

        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, tokenA),
                "User A's token should validate");
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, tokenB),
                "User B's token should validate");
    }

    @Test
    void tokenAndAssertAuth_TokenFromOneSecretValidatedWithAnother_ShouldFail() {
        // Token generated with one secret should not validate with another
        String secret1 = "firstSecretLongEnoughForHMACValidation!";
        String secret2 = "secondSecretLongEnoughForHMACValidation";

        String token = testUser.token(secret1);

        assertThrows(Unauthorized.class, () -> User.assertAuth(secret2, token),
                "Token should not validate with a different secret");
    }

    @Test
    void assertAuth_WithTokenHavingOnlyHeader_ShouldThrowUnauthorized() {
        // Token with only the header part should fail
        String headerOnly = "eyJhbGciOiJIUzI1NiJ9";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, headerOnly),
                "assertAuth should throw Unauthorized for header-only token");
    }

    @Test
    void assertAuth_WithTokenHavingHeaderAndPayloadOnly_ShouldThrowUnauthorized() {
        // Token with header and payload but no signature should fail
        String noSignature = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, noSignature),
                "assertAuth should throw Unauthorized for token without signature");
    }

    @Test
    void assertAuth_WithRandomBytes_ShouldThrowUnauthorized() {
        // Random base64-like string should fail
        String randomToken = "YWJjZGVm.Z2hpamts.bW5vcHFy";

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, randomToken),
                "assertAuth should throw Unauthorized for random base64 segments");
    }
}
```
