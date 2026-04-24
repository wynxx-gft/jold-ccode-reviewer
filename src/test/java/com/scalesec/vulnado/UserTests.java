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
    private static final String TEST_SECRET = "testSecretKeyForJWTTesting";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User("1", "testUser", "hashedPassword");
    }

    // Helper method to set up mock database connection with standard behavior
    private void setupMockConnection() throws Exception {
        when(Postgres.connection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
    }

    // Helper method to set up mock ResultSet to return a user
    private void setupMockResultSetWithUser(String userId, String username, String password) throws Exception {
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("user_id")).thenReturn(userId);
        when(mockResultSet.getString("username")).thenReturn(username);
        when(mockResultSet.getString("password")).thenReturn(password);
    }

    // Helper method to capture System.out output
    private ByteArrayOutputStream captureSystemOut() {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        return outContent;
    }

    // Helper method to capture System.err output
    private ByteArrayOutputStream captureSystemErr() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errContent));
        return errContent;
    }

    // Helper method to restore standard output streams
    private void restoreStreams() {
        System.setOut(System.out);
        System.setErr(System.err);
    }

    // --- Tests for User constructor ---

    @Test
    void constructor_InitializeFields_ShouldSetIdCorrectly() {
        // Verifies that the constructor correctly assigns the id field
        User user = new User("42", "alice", "hash123");
        assertEquals("42", user.id, "Constructor should set id field correctly");
    }

    @Test
    void constructor_InitializeFields_ShouldSetUsernameCorrectly() {
        // Verifies that the constructor correctly assigns the username field
        User user = new User("42", "alice", "hash123");
        assertEquals("alice", user.username, "Constructor should set username field correctly");
    }

    @Test
    void constructor_InitializeFields_ShouldSetHashedPasswordCorrectly() {
        // Verifies that the constructor correctly assigns the hashedPassword field
        User user = new User("42", "alice", "hash123");
        assertEquals("hash123", user.hashedPassword, "Constructor should set hashedPassword field correctly");
    }

    @Test
    void constructor_WithNullValues_ShouldAcceptNulls() {
        // Verifies that the constructor does not reject null values
        User user = new User(null, null, null);
        assertNull(user.id, "Constructor should accept null id");
        assertNull(user.username, "Constructor should accept null username");
        assertNull(user.hashedPassword, "Constructor should accept null hashedPassword");
    }

    @Test
    void constructor_WithEmptyStrings_ShouldAcceptEmptyStrings() {
        // Verifies that the constructor accepts empty strings
        User user = new User("", "", "");
        assertEquals("", user.id, "Constructor should accept empty string id");
        assertEquals("", user.username, "Constructor should accept empty string username");
        assertEquals("", user.hashedPassword, "Constructor should accept empty string hashedPassword");
    }

    // --- Tests for token() method ---

    @Test
    void token_GenerateToken_ShouldReturnNonNullValue() {
        // Verifies that token generation returns a non-null JWT string
        String token = testUser.token(TEST_SECRET);
        assertNotNull(token, "Generated token should not be null");
    }

    @Test
    void token_GenerateToken_ShouldReturnValidJWTFormat() {
        // Verifies that the token has the standard JWT three-part format (header.payload.signature)
        String token = testUser.token(TEST_SECRET);
        assertEquals(3, token.split("\\.").length, "Token should have three parts separated by dots");
    }

    @Test
    void token_GenerateToken_ShouldContainCorrectSubject() {
        // Verifies that the token's subject claim matches the user's username
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals(testUser.username, subject, "Token subject should match the user's username");
    }

    @Test
    void token_DifferentUsers_ShouldGenerateUniqueTokens() {
        // Verifies that different users produce different tokens
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    @Test
    void token_DifferentSecrets_ShouldGenerateDifferentTokens() {
        // Verifies that the same user with different secrets produces different tokens
        String token1 = testUser.token("secretKeyOneForTesting!!");
        String token2 = testUser.token("secretKeyTwoForTesting!!");

        assertNotEquals(token1, token2, "Tokens generated with different secrets should differ");
    }

    @Test
    void token_SameUserSameSecret_ShouldBeVerifiable() {
        // Verifies that a token generated can be verified with the same secret
        String token = testUser.token(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        assertDoesNotThrow(() -> Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token),
                "Token should be verifiable with the same secret key");
    }

    @Test
    void token_WithSpecialCharactersInUsername_ShouldGenerateValidToken() {
        // Verifies token generation works with special characters in username
        User specialUser = new User("3", "user@special!#$%", "hash");
        String token = specialUser.token(TEST_SECRET);
        assertNotNull(token, "Token should be generated even with special characters in username");
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
        assertEquals("user@special!#$%", subject, "Token subject should preserve special characters");
    }

    // --- Tests for assertAuth() method ---

    @Test
    void assertAuth_ValidToken_ShouldNotThrowException() {
        // Verifies that a valid token passes authentication without throwing
        String token = testUser.token(TEST_SECRET);
        assertDoesNotThrow(() -> User.assertAuth(TEST_SECRET, token),
                "assertAuth should not throw exception for a valid token");
    }

    @Test
    void assertAuth_InvalidToken_ShouldThrowUnauthorized() {
        // Verifies that a completely invalid token string throws Unauthorized
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, "invalidToken"),
                "assertAuth should throw Unauthorized for an invalid token");
    }

    @Test
    void assertAuth_ModifiedToken_ShouldThrowUnauthorized() {
        // Verifies that a tampered token (last character changed) throws Unauthorized
        String token = testUser.token(TEST_SECRET);
        String modifiedToken = token.substring(0, token.length() - 1) + "X";
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, modifiedToken),
                "assertAuth should throw Unauthorized for a modified token");
    }

    @Test
    void assertAuth_WrongSecret_ShouldThrowUnauthorized() {
        // Verifies that verifying a token with a different secret throws Unauthorized
        String token = testUser.token(TEST_SECRET);
        assertThrows(Unauthorized.class, () -> User.assertAuth("differentSecretKeyValue!!", token),
                "assertAuth should throw Unauthorized when verified with a different secret");
    }

    @Test
    void assertAuth_EmptyToken_ShouldThrowUnauthorized() {
        // Verifies that an empty token string throws Unauthorized
        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, ""),
                "assertAuth should throw Unauthorized for an empty token");
    }

    @Test
    void assertAuth_NullToken_ShouldThrowUnauthorized() {
        // Verifies that a null token throws Unauthorized (or an exception wrapping the cause)
        assertThrows(Exception.class, () -> User.assertAuth(TEST_SECRET, null),
                "assertAuth should throw an exception for a null token");
    }

    @Test
    void assertAuth_ExpiredToken_ShouldThrowUnauthorized() {
        // Verifies that an expired token throws Unauthorized
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
        String expiredToken = Jwts.builder()
                .setSubject(testUser.username)
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, expiredToken),
                "assertAuth should throw Unauthorized for an expired token");
    }

    @Test
    void assertAuth_InvalidToken_ShouldPrintStackTrace() {
        // Verifies that assertAuth prints stack trace information to stderr on failure
        ByteArrayOutputStream errContent = captureSystemErr();

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, "invalidToken"));

        assertTrue(errContent.toString().length() > 0,
                "assertAuth should print error information to stderr on exception");

        restoreStreams();
    }

    @Test
    void assertAuth_TokenSignedWithDifferentAlgorithm_ShouldThrowUnauthorized() {
        // Verifies that a token signed with a mismatched key throws Unauthorized
        SecretKey differentKey = Keys.hmacShaKeyFor("aCompletelyDifferentKeyVal!!".getBytes());
        String token = Jwts.builder()
                .setSubject("testUser")
                .signWith(differentKey)
                .compact();

        assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, token),
                "assertAuth should throw Unauthorized for a token signed with a different key");
    }

    // --- Tests for fetch() method ---

    @Test
    void fetch_ExistingUser_ShouldReturnUser() throws Exception {
        // Verifies that fetching an existing user returns a properly populated User object
        setupMockConnection();
        setupMockResultSetWithUser("1", "existingUser", "hashedPassword");

        User result = User.fetch("existingUser");

        assertNotNull(result, "Fetch should return a user for an existing username");
        assertEquals("existingUser", result.username, "Fetched user should have the correct username");
    }

    @Test
    void fetch_ExistingUser_ShouldReturnCorrectId() throws Exception {
        // Verifies that the fetched user has the correct id
        setupMockConnection();
        setupMockResultSetWithUser("99", "userWithId", "pw");

        User result = User.fetch("userWithId");

        assertNotNull(result, "Fetch should return a user");
        assertEquals("99", result.id, "Fetched user should have the correct id");
    }

    @Test
    void fetch_ExistingUser_ShouldReturnCorrectPassword() throws Exception {
        // Verifies that the fetched user has the correct hashedPassword
        setupMockConnection();
        setupMockResultSetWithUser("1", "pwUser", "superSecretHash");

        User result = User.fetch("pwUser");

        assertNotNull(result, "Fetch should return a user");
        assertEquals("superSecretHash", result.hashedPassword, "Fetched user should have the correct hashedPassword");
    }

    @Test
    void fetch_NonExistingUser_ShouldReturnNull() throws Exception {
        // Verifies that fetching a non-existing user returns null
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch("nonExistingUser");

        assertNull(result, "Fetch should return null for a non-existing username");
    }

    @Test
    void fetch_DatabaseException_ShouldReturnNull() throws Exception {
        // Verifies that a database exception results in null being returned
        when(Postgres.connection()).thenThrow(new RuntimeException("Database connection failed"));

        User result = User.fetch("exceptionUser");

        assertNull(result, "Fetch should return null when a database exception occurs");
    }

    @Test
    void fetch_ExecutesCorrectSQL_ShouldContainUsername() throws Exception {
        // Verifies that the correct SQL query is executed with the provided username
        String username = "sqlCheckUser";
        setupMockConnection();

        User.fetch(username);

        verify(mockStatement).executeQuery("select * from users where username = '" + username + "' limit 1");
    }

    @Test
    void fetch_ClosesConnection_ShouldCallCloseOnConnection() throws Exception {
        // Verifies that the database connection is closed after fetching
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("testUser");

        verify(mockConnection).close();
    }

    @Test
    void fetch_SQLInjectionAttempt_ShouldPassInputDirectlyToQuery() throws Exception {
        // Verifies behavior with SQL injection input (note: the code is vulnerable by design)
        String maliciousUsername = "user' OR '1'='1";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch(maliciousUsername);

        assertNull(result, "Fetch should return null for SQL injection attempt when no rows returned");
        verify(mockStatement).executeQuery("select * from users where username = '" + maliciousUsername + "' limit 1");
    }

    @Test
    void fetch_PrintsDatabaseOpenMessage_ShouldContainExpectedText() throws Exception {
        // Verifies that the fetch method prints the "Opened database successfully" message
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        ByteArrayOutputStream outContent = captureSystemOut();

        User.fetch("testUser");

        assertTrue(outContent.toString().contains("Opened database successfully"),
                "Fetch should print 'Opened database successfully' message");

        restoreStreams();
    }

    @Test
    void fetch_PrintsQuery_ShouldContainSQLStatement() throws Exception {
        // Verifies that the fetch method prints the SQL query being executed
        String username = "queryPrintUser";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        ByteArrayOutputStream outContent = captureSystemOut();

        User.fetch(username);

        String expectedQuery = "select * from users where username = '" + username + "' limit 1";
        assertTrue(outContent.toString().contains(expectedQuery),
                "Fetch should print the executed query to console");

        restoreStreams();
    }

    @Test
    void fetch_DatabaseException_ShouldPrintErrorMessage() throws Exception {
        // Verifies that database exceptions are printed to stderr
        RuntimeException testException = new RuntimeException("Test database exception");
        when(Postgres.connection()).thenThrow(testException);

        ByteArrayOutputStream errContent = captureSystemErr();

        User.fetch("exceptionUser");

        assertTrue(errContent.toString().contains("Test database exception"),
                "Fetch should print the exception message to stderr");

        restoreStreams();
    }

    @Test
    void fetch_MultipleResults_ShouldReturnFirstResult() throws Exception {
        // Verifies that when multiple rows exist, only the first one is returned
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(true, true, false);
        when(mockResultSet.getString("user_id")).thenReturn("1", "2");
        when(mockResultSet.getString("username")).thenReturn("duplicateUser", "duplicateUser");
        when(mockResultSet.getString("password")).thenReturn("password1", "password2");

        User result = User.fetch("duplicateUser");

        assertNotNull(result, "Fetch should return a user when multiple results exist");
        assertEquals("1", result.id, "Fetch should return the first user when multiple results exist");
    }

    @Test
    void fetch_EmptyUsername_ShouldExecuteQueryWithEmptyString() throws Exception {
        // Verifies that an empty username is passed through to the query
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch("");

        verify(mockStatement).executeQuery("select * from users where username = '' limit 1");
    }

    @Test
    void fetch_StatementCreationFails_ShouldReturnNull() throws Exception {
        // Verifies that failure during statement creation results in null
        when(Postgres.connection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenThrow(new RuntimeException("Statement creation failed"));

        User result = User.fetch("failUser");

        assertNull(result, "Fetch should return null when statement creation fails");
    }

    @Test
    void fetch_QueryExecutionFails_ShouldReturnNull() throws Exception {
        // Verifies that failure during query execution results in null
        when(Postgres.connection()).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query execution failed"));

        User result = User.fetch("queryFailUser");

        assertNull(result, "Fetch should return null when query execution fails");
    }

    @Test
    void fetch_ResultSetNextThrows_ShouldReturnNull() throws Exception {
        // Verifies that an exception from ResultSet.next() results in null
        setupMockConnection();
        when(mockResultSet.next()).thenThrow(new RuntimeException("ResultSet error"));

        User result = User.fetch("rsErrorUser");

        assertNull(result, "Fetch should return null when ResultSet.next() throws an exception");
    }

    @Test
    void fetch_PrintsResultSet_ShouldPrintRsWhenUserFound() throws Exception {
        // Verifies that the ResultSet object is printed to stdout when a user is found
        setupMockConnection();
        setupMockResultSetWithUser("1", "printUser", "pw");

        ByteArrayOutputStream outContent = captureSystemOut();

        User.fetch("printUser");

        // The code does System.out.println(rs), so toString of the mock should appear
        assertTrue(outContent.toString().contains(mockResultSet.toString()),
                "Fetch should print the ResultSet to console when a user is found");

        restoreStreams();
    }

    @Test
    void fetch_ExceptionClass_ShouldPrintClassNameInError() throws Exception {
        // Verifies that the exception class name is included in the error output
        when(Postgres.connection()).thenThrow(new IllegalStateException("State error"));

        ByteArrayOutputStream errContent = captureSystemErr();

        User.fetch("stateErrorUser");

        assertTrue(errContent.toString().contains("IllegalStateException"),
                "Fetch should print the exception class name to stderr");

        restoreStreams();
    }

    @Test
    void fetch_UsernameWithSpaces_ShouldPassUsernameAsIsToQuery() throws Exception {
        // Verifies that usernames with spaces are passed directly to the query without trimming
        String username = "  spacedUser  ";
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User.fetch(username);

        verify(mockStatement).executeQuery("select * from users where username = '" + username + "' limit 1");
    }

    @Test
    void fetch_LongUsername_ShouldHandleLongInput() throws Exception {
        // Verifies that a very long username is handled without error
        String longUsername = "a".repeat(1000);
        setupMockConnection();
        when(mockResultSet.next()).thenReturn(false);

        User result = User.fetch(longUsername);

        assertNull(result, "Fetch should return null for a non-existing long username");
        verify(mockStatement).executeQuery("select * from users where username = '" + longUsername + "' limit 1");
    }

    @Test
    void fetch_UnicodeUsername_ShouldHandleUnicodeCharacters() throws Exception {
        // Verifies that unicode characters in username are handled
        String unicodeUsername = "用户名テスト";
        setupMockConnection();
        setupMockResultSetWithUser("10", unicodeUsername, "unicodeHash");

        User result = User.fetch(unicodeUsername);

        assertNotNull(result, "Fetch should return a user with unicode username");
        assertEquals(unicodeUsername, result.username, "Fetched user should have the correct unicode username");
    }
}
