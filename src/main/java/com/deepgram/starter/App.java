/**
 * Java Live Text-to-Speech Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Live TTS API using the Deepgram Java SDK.
 * Forwards text messages from the browser to the SDK's Speak V1 WebSocket client,
 * and forwards binary audio chunks back to the browser.
 *
 * Routes:
 *   GET  /api/session                - Issue JWT session token
 *   GET  /api/metadata               - Project metadata from deepgram.toml
 *   WS   /api/live-text-to-speech    - WebSocket proxy to Deepgram TTS (auth required)
 *   GET  /health                     - Health check
 */
package com.deepgram.starter;

// ============================================================================
// SECTION 1: IMPORTS
// ============================================================================

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;

import com.deepgram.DeepgramClient;
import com.deepgram.resources.speak.v1.websocket.V1WebSocketClient;
import com.deepgram.resources.speak.v1.websocket.V1ConnectOptions;
import com.deepgram.resources.speak.v1.types.SpeakV1Text;
import com.deepgram.resources.speak.v1.types.SpeakV1Flush;
import com.deepgram.resources.speak.v1.types.SpeakV1Clear;
import com.deepgram.resources.speak.v1.types.SpeakV1Close;
import com.deepgram.types.SpeakV1Encoding;
import com.deepgram.types.SpeakV1Model;
import com.deepgram.types.SpeakV1SampleRate;

import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// ============================================================================
// SECTION 2: MAIN APPLICATION
// ============================================================================

public class App {

    // ========================================================================
    // SECTION 3: CONFIGURATION
    // ========================================================================

    private static final Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

    private static final String DEEPGRAM_API_KEY = getRequiredEnv("DEEPGRAM_API_KEY");
    private static final int PORT = Integer.parseInt(getEnv("PORT", "8081"));
    private static final String HOST = getEnv("HOST", "0.0.0.0");

    /** Session secret: use configured value or generate a random one */
    private static final String SESSION_SECRET = getEnv("SESSION_SECRET", generateRandomSecret());
    private static final Algorithm JWT_ALGORITHM = Algorithm.HMAC256(SESSION_SECRET);
    private static final JWTVerifier JWT_VERIFIER = JWT.require(JWT_ALGORITHM).build();
    private static final long JWT_EXPIRY_SECONDS = 3600; // 1 hour

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final TomlMapper TOML_MAPPER = new TomlMapper();

    /** Map of browser WsContext -> SDK V1WebSocketClient for cleanup */
    private static final ConcurrentHashMap<WsContext, V1WebSocketClient> activeConnections =
            new ConcurrentHashMap<>();

    // ========================================================================
    // SECTION 4: ENVIRONMENT HELPERS
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
    // SECTION 5: SESSION AUTH - JWT tokens for production security
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
    // SECTION 6: METADATA - Read deepgram.toml [meta] section
    // ========================================================================

    /**
     * Reads and returns the [meta] section from deepgram.toml as a Map.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> readMetadata() throws Exception {
        try (InputStream is = App.class.getClassLoader().getResourceAsStream("deepgram.toml")) {
            if (is == null) {
                // Fall back to filesystem for local development
                File file = new File("deepgram.toml");
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
    // SECTION 7: WEBSOCKET ROUTE - Live Text-to-Speech Proxy
    // ========================================================================

    /**
     * Configures the WebSocket endpoint for live text-to-speech.
     * Acts as a bidirectional proxy: browser <-> Javalin <-> Deepgram SDK Speak V1 WebSocket.
     *
     * The browser sends JSON text messages (e.g., { type: "Speak", text: "..." })
     * and receives binary audio chunks back. The SDK handles the outbound connection
     * to Deepgram, authentication, and WebSocket lifecycle.
     *
     * @param ws Javalin WebSocket config
     */
    private static void handleLiveTextToSpeech(WsConfig ws) {

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

            // Parse query parameters from the WebSocket URL
            String model = ctx.queryParam("model") != null ? ctx.queryParam("model") : "aura-asteria-en";
            String encoding = ctx.queryParam("encoding") != null ? ctx.queryParam("encoding") : "linear16";
            String sampleRate = ctx.queryParam("sample_rate") != null ? ctx.queryParam("sample_rate") : "48000";

            System.out.println("Connecting to Deepgram TTS: model=" + model
                    + ", encoding=" + encoding + ", sample_rate=" + sampleRate);

            // Create SDK client for this connection
            DeepgramClient dgClient = DeepgramClient.builder()
                    .apiKey(DEEPGRAM_API_KEY)
                    .build();

            V1WebSocketClient dgWs = dgClient.speak().v1().v1WebSocket();

            // Forward binary audio chunks from Deepgram to browser
            dgWs.onSpeakV1Audio(audioBytes -> {
                try {
                    if (ctx.session.isOpen()) {
                        ctx.send(ByteBuffer.wrap(audioBytes.toByteArray()));
                    }
                } catch (Exception e) {
                    System.err.println("Error forwarding audio to browser: " + e.getMessage());
                }
            });

            // Forward JSON text messages (metadata, flushed, warning, etc.) from Deepgram to browser
            dgWs.onMessage(json -> {
                try {
                    // Only forward JSON text messages, not binary (audio handled by onSpeakV1Audio)
                    if (ctx.session.isOpen()) {
                        ctx.send(json);
                    }
                } catch (Exception e) {
                    System.err.println("Error forwarding message to browser: " + e.getMessage());
                }
            });

            dgWs.onError(e -> {
                System.err.println("Deepgram WebSocket error: " + e.getMessage());
                try {
                    if (ctx.session.isOpen()) {
                        String errorJson = JSON_MAPPER.writeValueAsString(Map.of(
                                "type", "Error",
                                "description", e.getMessage() != null ? e.getMessage() : "Deepgram connection error",
                                "code", "PROVIDER_ERROR"
                        ));
                        ctx.send(errorJson);
                    }
                } catch (Exception ex) {
                    System.err.println("Failed to send error to client: " + ex.getMessage());
                }
            });

            dgWs.onDisconnected(reason -> {
                System.out.println("Deepgram TTS connection closed: " + reason);
                try {
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1000, "Deepgram disconnected");
                    }
                } catch (Exception ignored) {}
                activeConnections.remove(ctx);
            });

            // Build connection options using SDK builder
            V1ConnectOptions.Builder optionsBuilder = V1ConnectOptions.builder();
            optionsBuilder
                    .model(SpeakV1Model.valueOf(model))
                    .encoding(SpeakV1Encoding.valueOf(encoding))
                    .sampleRate(SpeakV1SampleRate.valueOf(sampleRate));
            V1ConnectOptions options = optionsBuilder.build();

            // Connect to Deepgram via SDK
            dgWs.connect(options).thenRun(() -> {
                activeConnections.put(ctx, dgWs);
                System.out.println("Live TTS session started (model=" + model + ")");
            }).exceptionally(e -> {
                System.err.println("Failed to connect to Deepgram TTS: " + e.getMessage());
                try {
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1011, "Failed to connect to Deepgram");
                    }
                } catch (Exception ignored) {}
                return null;
            });
        });

        // Forward text messages from client to Deepgram via SDK
        // The client sends JSON messages like { type: "Speak", text: "..." }
        ws.onMessage(ctx -> {
            V1WebSocketClient dgWs = activeConnections.get(ctx);
            if (dgWs != null) {
                try {
                    String message = ctx.message();
                    JsonNode node = JSON_MAPPER.readTree(message);
                    String type = node.has("type") ? node.get("type").asText() : "";

                    switch (type) {
                        case "Speak":
                            String text = node.has("text") ? node.get("text").asText() : "";
                            dgWs.sendText(SpeakV1Text.builder().text(text).build());
                            break;
                        case "Flush":
                            dgWs.sendFlush(SpeakV1Flush.builder()
                                    .type(com.deepgram.resources.speak.v1.types.SpeakV1FlushType.FLUSH).build());
                            break;
                        case "Clear":
                            dgWs.sendClear(SpeakV1Clear.builder()
                                    .type(com.deepgram.resources.speak.v1.types.SpeakV1ClearType.CLEAR).build());
                            break;
                        case "Close":
                            dgWs.sendClose(SpeakV1Close.builder()
                                    .type(com.deepgram.resources.speak.v1.types.SpeakV1CloseType.CLOSE).build());
                            break;
                        default:
                            // Default: try sending as Speak text
                            String defaultText = node.has("text") ? node.get("text").asText() : message;
                            dgWs.sendText(SpeakV1Text.builder().text(defaultText).build());
                            break;
                    }
                } catch (Exception e) {
                    System.err.println("Error forwarding message to Deepgram: " + e.getMessage());
                }
            }
        });

        // Forward binary messages from client to Deepgram (if needed)
        ws.onBinaryMessage(ctx -> {
            // Binary messages from client are not typical for TTS but forward if present
            V1WebSocketClient dgWs = activeConnections.get(ctx);
            if (dgWs != null) {
                byte[] data = ctx.data();
                int offset = ctx.offset();
                int length = ctx.length();
                byte[] bytes = new byte[length];
                System.arraycopy(data, offset, bytes, 0, length);
                dgWs.sendText(SpeakV1Text.builder().text(new String(bytes)).build());
            }
        });

        // Handle client disconnect - clean up Deepgram connection
        ws.onClose(ctx -> {
            System.out.println("Client disconnected: " + ctx.status() + " " + ctx.reason());
            V1WebSocketClient dgWs = activeConnections.remove(ctx);
            if (dgWs != null) {
                try {
                    dgWs.disconnect();
                } catch (Exception ignored) {}
            }
        });

        // Handle client errors
        ws.onError(ctx -> {
            System.err.println("Client WebSocket error: " + (ctx.error() != null ? ctx.error().getMessage() : "unknown"));
            V1WebSocketClient dgWs = activeConnections.remove(ctx);
            if (dgWs != null) {
                try {
                    dgWs.disconnect();
                } catch (Exception ignored) {}
            }
        });
    }

    // ========================================================================
    // SECTION 8: MAIN - Server setup and startup
    // ========================================================================

    /**
     * Application entry point. Loads configuration, validates the API key,
     * and starts the Javalin HTTP server with WebSocket support.
     *
     * @param args Command-line arguments (unused)
     */
    public static void main(String[] args) throws Exception {

        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> {
                    rule.anyHost();
                });
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

        app.ws("/api/live-text-to-speech", App::handleLiveTextToSpeech);

        // ====================================================================
        // START SERVER
        // ====================================================================

        app.start(HOST, PORT);

        System.out.println();
        System.out.println("=".repeat(70));
        System.out.println("  Backend API running at http://localhost:" + PORT);
        System.out.println("  GET  /api/session");
        System.out.println("  WS   /api/live-text-to-speech (auth required)");
        System.out.println("  GET  /api/metadata");
        System.out.println("  GET  /health");
        System.out.println("=".repeat(70));
        System.out.println();
    }
}
