/**
 * Java Live Text-to-Speech Starter - Javalin Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Live TTS API.
 * Forwards all messages (JSON text and binary audio) bidirectionally
 * between client and Deepgram.
 *
 * Routes:
 *   GET  /api/session                - Issue JWT session token
 *   GET  /api/metadata               - Project metadata from deepgram.toml
 *   WS   /api/live-text-to-speech    - WebSocket proxy to Deepgram TTS (auth required)
 *   GET  /health                     - Health check
 */
package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsContext;

import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.StatusCode;
import org.eclipse.jetty.websocket.api.annotations.*;
import org.eclipse.jetty.websocket.client.ClientUpgradeRequest;
import org.eclipse.jetty.websocket.client.WebSocketClient;

import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// ============================================================================
// MAIN APPLICATION
// ============================================================================

public class App {

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    private static final Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

    private static final String DEEPGRAM_API_KEY = getRequiredEnv("DEEPGRAM_API_KEY");
    private static final String DEEPGRAM_TTS_URL = "wss://api.deepgram.com/v1/speak";
    private static final int PORT = Integer.parseInt(getEnv("PORT", "8081"));
    private static final String HOST = getEnv("HOST", "0.0.0.0");

    /** Session secret: use configured value or generate a random one */
    private static final String SESSION_SECRET = getEnv("SESSION_SECRET", generateRandomSecret());
    private static final Algorithm JWT_ALGORITHM = Algorithm.HMAC256(SESSION_SECRET);
    private static final JWTVerifier JWT_VERIFIER = JWT.require(JWT_ALGORITHM).build();
    private static final long JWT_EXPIRY_SECONDS = 3600; // 1 hour

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final TomlMapper TOML_MAPPER = new TomlMapper();

    /** Track active client WebSocket contexts for graceful shutdown */
    private static final Set<WsContext> activeConnections = ConcurrentHashMap.newKeySet();

    /**
     * Map each client WsContext to its upstream Deepgram session.
     * WsContext is used as the key per Javalin's recommended pattern --
     * each connection gets its own unique WsContext instance.
     */
    private static final Map<WsContext, Session> deepgramSessions = new ConcurrentHashMap<>();

    /** Shared Jetty WebSocket client for outbound Deepgram connections */
    private static final WebSocketClient wsClient = new WebSocketClient();

    // ========================================================================
    // ENVIRONMENT HELPERS
    // ========================================================================

    /**
     * Gets an environment variable from .env or system environment.
     * Exits with a helpful message if a required variable is missing.
     */
    private static String getRequiredEnv(String key) {
        String sysEnv = System.getenv(key);
        String value = sysEnv != null ? dotenv.get(key, sysEnv) : dotenv.get(key);
        if (value == null || value.isBlank()) {
            System.err.println("ERROR: " + key + " environment variable is required");
            System.err.println("Please copy sample.env to .env and add your API key");
            System.exit(1);
        }
        return value;
    }

    /**
     * Gets an environment variable with a default fallback.
     */
    private static String getEnv(String key, String defaultValue) {
        String sysEnv = System.getenv(key);
        String value = sysEnv != null ? dotenv.get(key, sysEnv) : dotenv.get(key);
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }

    /**
     * Generates a random 32-byte hex secret for JWT signing.
     */
    private static String generateRandomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(64);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ========================================================================
    // SESSION AUTH - JWT tokens for production security
    // ========================================================================

    /**
     * Creates a signed JWT with the current timestamp and 1-hour expiry.
     */
    private static String createSessionToken() {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuedAt(now)
                .withExpiresAt(now.plusSeconds(JWT_EXPIRY_SECONDS))
                .sign(JWT_ALGORITHM);
    }

    /**
     * Validates JWT from WebSocket subprotocol: access_token.<jwt>
     * Returns the full protocol string if valid, null if invalid.
     */
    private static String validateWsToken(String protocols) {
        if (protocols == null || protocols.isBlank()) return null;
        String[] parts = protocols.split(",");
        for (String part : parts) {
            String proto = part.trim();
            if (proto.startsWith("access_token.")) {
                String token = proto.substring("access_token.".length());
                try {
                    JWT_VERIFIER.verify(token);
                    return proto;
                } catch (JWTVerificationException e) {
                    return null;
                }
            }
        }
        return null;
    }

    // ========================================================================
    // METADATA - Read deepgram.toml [meta] section
    // ========================================================================

    /**
     * Reads and returns the [meta] section from deepgram.toml as a Map.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> readMetadata() throws Exception {
        try (InputStream is = App.class.getClassLoader().getResourceAsStream("deepgram.toml")) {
            if (is == null) {
                // Fall back to filesystem for local development
                java.io.File file = new java.io.File("deepgram.toml");
                if (!file.exists()) {
                    throw new RuntimeException("deepgram.toml not found");
                }
                Map<String, Object> config = TOML_MAPPER.readValue(file, Map.class);
                Map<String, Object> meta = (Map<String, Object>) config.get("meta");
                if (meta == null) {
                    throw new RuntimeException("Missing [meta] section in deepgram.toml");
                }
                return meta;
            }
            Map<String, Object> config = TOML_MAPPER.readValue(is, Map.class);
            Map<String, Object> meta = (Map<String, Object>) config.get("meta");
            if (meta == null) {
                throw new RuntimeException("Missing [meta] section in deepgram.toml");
            }
            return meta;
        }
    }

    // ========================================================================
    // DEEPGRAM WEBSOCKET HANDLER (upstream connection)
    // ========================================================================

    /**
     * Jetty WebSocket endpoint that receives messages from Deepgram and
     * forwards them to the corresponding client WebSocket.
     */
    @WebSocket
    public static class DeepgramSocket {
        private final WsContext clientCtx;

        public DeepgramSocket(WsContext clientCtx) {
            this.clientCtx = clientCtx;
        }

        @OnWebSocketConnect
        public void onOpen(Session session) {
            System.out.println("Connected to Deepgram TTS API");
            deepgramSessions.put(clientCtx, session);
        }

        @OnWebSocketMessage
        public void onTextMessage(Session session, String message) {
            // Forward JSON text messages from Deepgram to client
            if (clientCtx.session.isOpen()) {
                clientCtx.send(message);
            }
        }

        @OnWebSocketMessage
        public void onBinaryMessage(byte[] payload, int offset, int len) {
            // Forward binary audio data from Deepgram to client
            if (clientCtx.session.isOpen()) {
                byte[] data = new byte[len];
                System.arraycopy(payload, offset, data, 0, len);
                clientCtx.send(ByteBuffer.wrap(data));
            }
        }

        @OnWebSocketError
        public void onError(Session session, Throwable error) {
            System.err.println("Deepgram WebSocket error: " + error.getMessage());
            if (clientCtx.session.isOpen()) {
                try {
                    String errorJson = JSON_MAPPER.writeValueAsString(Map.of(
                            "type", "Error",
                            "description", error.getMessage() != null ? error.getMessage() : "Deepgram connection error",
                            "code", "PROVIDER_ERROR"
                    ));
                    clientCtx.send(errorJson);
                } catch (Exception e) {
                    System.err.println("Failed to send error to client: " + e.getMessage());
                }
            }
        }

        @OnWebSocketClose
        public void onClose(int statusCode, String reason) {
            System.out.println("Deepgram connection closed: " + statusCode + " " + (reason != null ? reason : ""));
            deepgramSessions.remove(clientCtx);
            if (clientCtx.session.isOpen()) {
                int closeCode = getSafeCloseCode(statusCode);
                clientCtx.closeSession(closeCode, reason != null ? reason : "");
            }
        }

        /**
         * Returns a safe WebSocket close code, avoiding reserved codes.
         */
        private int getSafeCloseCode(int code) {
            int[] reserved = {1004, 1005, 1006, 1015};
            if (code >= 1000 && code <= 4999) {
                for (int r : reserved) {
                    if (code == r) return 1000;
                }
                return code;
            }
            return 1000;
        }
    }

    // ========================================================================
    // MAIN - Server setup and startup
    // ========================================================================

    public static void main(String[] args) throws Exception {
        // Start the shared WebSocket client for outbound Deepgram connections
        wsClient.start();

        Javalin app = Javalin.create(config -> {
            // Configure Jetty server for WebSocket upgrade handling
            config.jetty.modifyServer(server -> {
                // Server-level configuration if needed
            });
        });

        // ====================================================================
        // HTTP ROUTES
        // ====================================================================

        /**
         * GET /api/session - Issues a signed JWT for session authentication.
         */
        app.get("/api/session", ctx -> {
            String token = createSessionToken();
            ctx.json(Map.of("token", token));
        });

        /**
         * GET /health - Health check endpoint.
         */
        app.get("/health", ctx -> {
            ctx.json(Map.of("status", "ok"));
        });

        /**
         * GET /api/metadata - Returns project metadata from deepgram.toml.
         */
        app.get("/api/metadata", ctx -> {
            try {
                Map<String, Object> meta = readMetadata();
                ctx.json(meta);
            } catch (Exception e) {
                System.err.println("Error reading metadata: " + e.getMessage());
                ctx.status(500).json(Map.of(
                        "error", "INTERNAL_SERVER_ERROR",
                        "message", "Failed to read metadata from deepgram.toml"
                ));
            }
        });

        // ====================================================================
        // WEBSOCKET PROXY - /api/live-text-to-speech
        // ====================================================================

        app.ws("/api/live-text-to-speech", ws -> {

            ws.onConnect(ctx -> {
                // Validate JWT from subprotocol header
                String protocols = ctx.header("Sec-WebSocket-Protocol");
                String validProto = validateWsToken(protocols);
                if (validProto == null) {
                    System.out.println("WebSocket auth failed: invalid or missing token");
                    ctx.closeSession(4401, "Unauthorized");
                    return;
                }

                System.out.println("Client connected to /api/live-text-to-speech");
                activeConnections.add(ctx);

                // Parse query parameters from the WebSocket URL
                String model = ctx.queryParam("model") != null ? ctx.queryParam("model") : "aura-asteria-en";
                String encoding = ctx.queryParam("encoding") != null ? ctx.queryParam("encoding") : "linear16";
                String sampleRate = ctx.queryParam("sample_rate") != null ? ctx.queryParam("sample_rate") : "48000";
                String container = ctx.queryParam("container") != null ? ctx.queryParam("container") : "none";

                // Build Deepgram WebSocket URL with query parameters
                String deepgramUrl = DEEPGRAM_TTS_URL
                        + "?model=" + model
                        + "&encoding=" + encoding
                        + "&sample_rate=" + sampleRate
                        + "&container=" + container;

                System.out.println("Connecting to Deepgram TTS: model=" + model
                        + ", encoding=" + encoding + ", sample_rate=" + sampleRate);

                try {
                    // Create outbound WebSocket connection to Deepgram
                    DeepgramSocket deepgramSocket = new DeepgramSocket(ctx);
                    ClientUpgradeRequest request = new ClientUpgradeRequest();
                    request.setHeader("Authorization", "Token " + DEEPGRAM_API_KEY);

                    wsClient.connect(deepgramSocket, new URI(deepgramUrl), request);
                } catch (Exception e) {
                    System.err.println("Error connecting to Deepgram: " + e.getMessage());
                    if (ctx.session.isOpen()) {
                        String errorJson = JSON_MAPPER.writeValueAsString(Map.of(
                                "type", "Error",
                                "description", "Failed to establish proxy connection",
                                "code", "CONNECTION_FAILED"
                        ));
                        ctx.send(errorJson);
                        ctx.closeSession(1011, "Failed to connect to Deepgram");
                    }
                }
            });

            ws.onMessage(ctx -> {
                // Forward text messages from client to Deepgram
                Session deepgramSession = deepgramSessions.get(ctx);
                if (deepgramSession != null && deepgramSession.isOpen()) {
                    deepgramSession.getRemote().sendString(ctx.message());
                }
            });

            ws.onBinaryMessage(ctx -> {
                // Forward binary messages from client to Deepgram
                Session deepgramSession = deepgramSessions.get(ctx);
                if (deepgramSession != null && deepgramSession.isOpen()) {
                    byte[] data = ctx.data();
                    int offset = ctx.offset();
                    int length = ctx.length();
                    byte[] bytes = new byte[length];
                    System.arraycopy(data, offset, bytes, 0, length);
                    deepgramSession.getRemote().sendBytes(ByteBuffer.wrap(bytes));
                }
            });

            ws.onClose(ctx -> {
                System.out.println("Client disconnected: " + ctx.status() + " " + ctx.reason());
                activeConnections.remove(ctx);

                // Close the upstream Deepgram connection
                Session deepgramSession = deepgramSessions.remove(ctx);
                if (deepgramSession != null && deepgramSession.isOpen()) {
                    deepgramSession.close(StatusCode.NORMAL, "Client disconnected");
                }
            });

            ws.onError(ctx -> {
                System.err.println("Client WebSocket error: " + (ctx.error() != null ? ctx.error().getMessage() : "unknown"));

                // Close the upstream Deepgram connection on client error
                Session deepgramSession = deepgramSessions.remove(ctx);
                if (deepgramSession != null && deepgramSession.isOpen()) {
                    deepgramSession.close(StatusCode.NORMAL, "Client error");
                }
            });
        });

        // ====================================================================
        // GRACEFUL SHUTDOWN
        // ====================================================================

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutdown signal received: starting graceful shutdown...");

            // Close all active client WebSocket connections
            System.out.println("Closing " + activeConnections.size() + " active WebSocket connection(s)...");
            for (WsContext wsCtx : activeConnections) {
                try {
                    if (wsCtx.session.isOpen()) {
                        wsCtx.closeSession(1001, "Server shutting down");
                    }
                } catch (Exception e) {
                    System.err.println("Error closing WebSocket: " + e.getMessage());
                }
            }

            // Close all upstream Deepgram connections
            for (Session session : deepgramSessions.values()) {
                try {
                    if (session.isOpen()) {
                        session.close(StatusCode.NORMAL, "Server shutting down");
                    }
                } catch (Exception e) {
                    System.err.println("Error closing Deepgram session: " + e.getMessage());
                }
            }

            // Stop the WebSocket client
            try {
                wsClient.stop();
            } catch (Exception e) {
                System.err.println("Error stopping WebSocket client: " + e.getMessage());
            }

            System.out.println("Shutdown complete");
        }));

        // ====================================================================
        // START SERVER
        // ====================================================================

        app.start(HOST, PORT);

        System.out.println();
        System.out.println("=".repeat(70));
        System.out.println("Backend API Server running at http://localhost:" + PORT);
        System.out.println();
        System.out.println("  GET  /api/session");
        System.out.println("  WS   /api/live-text-to-speech (auth required)");
        System.out.println("  GET  /api/metadata");
        System.out.println("  GET  /health");
        System.out.println("=".repeat(70));
        System.out.println();
    }
}
