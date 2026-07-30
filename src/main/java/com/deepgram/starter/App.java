/**
 * Java Live Text-to-Speech Starter - Javalin Backend Server
 *
 * Bridges a browser WebSocket to Deepgram's Live (streaming) Text-to-Speech
 * using the official Deepgram Java SDK's `client.speak().v1().v1WebSocket()`.
 * The SDK manages the outbound connection, auth, and binary-audio framing; the
 * browser-facing contract is unchanged (raw Deepgram JSON control messages plus
 * binary audio are forwarded verbatim in both directions).
 *
 * Routes:
 *   GET  /api/session                - Issue JWT session token
 *   GET  /api/metadata               - Project metadata from deepgram.toml
 *   WS   /api/live-text-to-speech    - Streaming TTS bridge to Deepgram (auth required)
 *   GET  /health                     - Health check
 */
package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import com.deepgram.DeepgramClient;
import com.deepgram.resources.speak.v1.types.SpeakV1Clear;
import com.deepgram.resources.speak.v1.types.SpeakV1ClearType;
import com.deepgram.resources.speak.v1.types.SpeakV1Close;
import com.deepgram.resources.speak.v1.types.SpeakV1CloseType;
import com.deepgram.resources.speak.v1.types.SpeakV1Flush;
import com.deepgram.resources.speak.v1.types.SpeakV1FlushType;
import com.deepgram.resources.speak.v1.types.SpeakV1Text;
import com.deepgram.resources.speak.v1.websocket.V1ConnectOptions;
import com.deepgram.resources.speak.v1.websocket.V1WebSocketClient;
import com.deepgram.types.SpeakV1Encoding;
import com.deepgram.types.SpeakV1Model;
import com.deepgram.types.SpeakV1SampleRate;

import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;

import java.io.InputStream;
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
    private static final int PORT = Integer.parseInt(getEnv("PORT", "8081"));
    private static final String HOST = getEnv("HOST", "0.0.0.0");

    /** Session secret: use configured value or generate a random one */
    private static final String SESSION_SECRET = getEnv("SESSION_SECRET", generateRandomSecret());
    private static final Algorithm JWT_ALGORITHM = Algorithm.HMAC256(SESSION_SECRET);
    private static final JWTVerifier JWT_VERIFIER = JWT.require(JWT_ALGORITHM).build();
    private static final long JWT_EXPIRY_SECONDS = 3600; // 1 hour

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final TomlMapper TOML_MAPPER = new TomlMapper();

    private static final Set<Integer> RESERVED_CLOSE_CODES = Set.of(1004, 1005, 1006, 1015);

    /** Track active client WebSocket contexts for graceful shutdown */
    private static final Set<WsContext> activeConnections = ConcurrentHashMap.newKeySet();

    /** One SDK client, reused across connections; the browser never sees the API key. */
    private static DeepgramClient deepgram;

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

    /**
     * Returns a safe WebSocket close code, avoiding reserved codes.
     */
    private static int getSafeCloseCode(int code) {
        if (code >= 1000 && code <= 4999 && !RESERVED_CLOSE_CODES.contains(code)) {
            return code;
        }
        return 1000;
    }

    private static String firstNonEmpty(String value, String fallback) {
        return (value == null || value.isEmpty()) ? fallback : value;
    }

    private static void sendError(WsContext ctx, String description, String code) {
        try {
            if (!ctx.session.isOpen()) return;
            ctx.send(JSON_MAPPER.writeValueAsString(Map.of(
                    "type", "Error",
                    "description", description != null ? description : "Deepgram connection error",
                    "code", code)));
        } catch (Exception e) {
            System.err.println("Failed to send error to client: " + e.getMessage());
        }
    }

    // ========================================================================
    // DEEPGRAM BRIDGE (per browser connection)
    // ========================================================================

    /**
     * Per-connection bridge to a Deepgram Live TTS WebSocket. Buffers browser
     * control messages that arrive before the Deepgram socket is open.
     */
    static final class TtsBridge {
        private final V1WebSocketClient ws;
        private boolean ready = false;
        private final List<JsonNode> pending = new ArrayList<>();

        TtsBridge(V1WebSocketClient ws) {
            this.ws = ws;
        }

        synchronized void dispatch(JsonNode msg) {
            if (!ready) {
                pending.add(msg);
                return;
            }
            send(msg);
        }

        synchronized void markReady() {
            ready = true;
            for (JsonNode m : pending) {
                send(m);
            }
            pending.clear();
        }

        private void send(JsonNode msg) {
            String type = msg.path("type").asText("");
            try {
                switch (type) {
                    case "Speak":
                        ws.sendText(SpeakV1Text.builder()
                                .text(msg.path("text").asText(""))
                                .build());
                        break;
                    case "Flush":
                        ws.sendFlush(SpeakV1Flush.builder()
                                .type(SpeakV1FlushType.FLUSH)
                                .build());
                        break;
                    case "Clear":
                        ws.sendClear(SpeakV1Clear.builder()
                                .type(SpeakV1ClearType.CLEAR)
                                .build());
                        break;
                    case "Close":
                        ws.sendClose(SpeakV1Close.builder()
                                .type(SpeakV1CloseType.CLOSE)
                                .build());
                        break;
                    default:
                        System.out.println("Ignoring unknown client message type: " + type);
                }
            } catch (Exception e) {
                System.err.println("Failed to forward message to Deepgram: " + e.getMessage());
            }
        }

        void disconnect() {
            try {
                ws.disconnect();
            } catch (Exception ignored) {
                // already closed
            }
        }
    }

    // ========================================================================
    // MAIN - Server setup and startup
    // ========================================================================

    public static void main(String[] args) throws Exception {
        // One SDK client, reused across connections. Reads DEEPGRAM_API_KEY.
        deepgram = DeepgramClient.builder().apiKey(DEEPGRAM_API_KEY).build();

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
        // WEBSOCKET BRIDGE - /api/live-text-to-speech
        // ====================================================================

        app.ws("/api/live-text-to-speech", App::handleTtsWebSocket);

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

    /**
     * Per-connection bridge between a browser WebSocket and a Deepgram Live TTS
     * WebSocket (via the SDK). Control JSON and binary audio are forwarded
     * verbatim so the frontend contract is unchanged.
     */
    private static void handleTtsWebSocket(WsConfig ws) {

        ws.onConnect(ctx -> {
            // Validate JWT from subprotocol header
            String protocols = ctx.header("Sec-WebSocket-Protocol");
            if (validateWsToken(protocols) == null) {
                System.out.println("WebSocket auth failed: invalid or missing token");
                ctx.closeSession(4401, "Unauthorized");
                return;
            }

            System.out.println("Client connected to /api/live-text-to-speech");
            activeConnections.add(ctx);

            // Parse query parameters from the WebSocket URL (same contract as before)
            String model = firstNonEmpty(ctx.queryParam("model"), "aura-asteria-en");
            String encoding = firstNonEmpty(ctx.queryParam("encoding"), "linear16");
            String sampleRate = firstNonEmpty(ctx.queryParam("sample_rate"), "48000");
            String container = firstNonEmpty(ctx.queryParam("container"), "none");

            System.out.println("Connecting to Deepgram TTS: model=" + model
                    + ", encoding=" + encoding + ", sample_rate=" + sampleRate);

            V1WebSocketClient dgSocket = deepgram.speak().v1().v1WebSocket();
            TtsBridge bridge = new TtsBridge(dgSocket);
            ctx.attribute("bridge", bridge);

            // Deepgram -> browser: binary audio, forwarded verbatim.
            dgSocket.onSpeakV1Audio(audio -> {
                try {
                    if (ctx.session.isOpen()) {
                        ctx.send(ByteBuffer.wrap(audio.toByteArray()));
                    }
                } catch (Exception e) {
                    System.err.println("Error forwarding audio to client: " + e.getMessage());
                }
            });

            // Deepgram -> browser: control JSON (Metadata/Flushed/Cleared/Warning/...),
            // forwarded verbatim to preserve the browser message contract.
            dgSocket.onMessage(raw -> {
                try {
                    if (ctx.session.isOpen()) {
                        ctx.send(raw);
                    }
                } catch (Exception e) {
                    System.err.println("Error forwarding control message to client: " + e.getMessage());
                }
            });

            dgSocket.onError(error -> {
                System.err.println("Deepgram WebSocket error: " + error.getMessage());
                sendError(ctx, error.getMessage(), "PROVIDER_ERROR");
                if (ctx.session.isOpen()) {
                    ctx.closeSession(1011, "Deepgram connection error");
                }
            });

            dgSocket.onDisconnected(reason -> {
                System.out.println("Deepgram connection closed: " + reason.getCode() + " "
                        + (reason.getReason() != null ? reason.getReason() : ""));
                if (ctx.session.isOpen()) {
                    ctx.closeSession(getSafeCloseCode(reason.getCode()),
                            reason.getReason() != null ? reason.getReason() : "");
                }
            });

            V1ConnectOptions.Builder optionsBuilder = V1ConnectOptions.builder()
                    .model(SpeakV1Model.valueOf(model))
                    .encoding(SpeakV1Encoding.valueOf(encoding))
                    .sampleRate(SpeakV1SampleRate.valueOf(sampleRate));
            // `container` has no typed connect option; pass it through as a query param
            // (escape hatch) so the browser-facing contract is preserved.
            if (container != null && !container.isEmpty()) {
                optionsBuilder.additionalProperty("container", container);
            }

            dgSocket.connect(optionsBuilder.build()).whenComplete((v, err) -> {
                if (err != null) {
                    System.err.println("Deepgram connection failed to open: " + err.getMessage());
                    sendError(ctx, "Failed to establish proxy connection", "CONNECTION_FAILED");
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1011, "Failed to connect to Deepgram");
                    }
                    return;
                }
                System.out.println("Connected to Deepgram TTS API");
                bridge.markReady();
            });
        });

        // browser -> Deepgram (JSON control messages: Speak/Flush/Clear/Close)
        ws.onMessage(ctx -> {
            TtsBridge bridge = ctx.attribute("bridge");
            if (bridge == null) return;
            try {
                JsonNode msg = JSON_MAPPER.readTree(ctx.message());
                bridge.dispatch(msg);
            } catch (Exception e) {
                System.err.println("Ignoring non-JSON message from client");
            }
        });

        // browser -> Deepgram binary is not used by the Live TTS contract; ignore.
        ws.onBinaryMessage(ctx -> {
            // no-op: the TTS browser client sends only JSON control messages
        });

        ws.onClose(ctx -> {
            System.out.println("Client disconnected: " + ctx.status() + " " + ctx.reason());
            activeConnections.remove(ctx);
            TtsBridge bridge = ctx.attribute("bridge");
            if (bridge != null) {
                bridge.disconnect();
            }
        });

        ws.onError(ctx -> {
            System.err.println("Client WebSocket error: "
                    + (ctx.error() != null ? ctx.error().getMessage() : "unknown"));
            TtsBridge bridge = ctx.attribute("bridge");
            if (bridge != null) {
                bridge.disconnect();
            }
        });
    }
}
