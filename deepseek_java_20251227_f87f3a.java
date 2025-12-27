// =============================================
// PART 1: CONFIGURATION CLASSES
// =============================================

import org.jsmpp.bean.*;
import org.jsmpp.session.*;
import org.jsmpp.extra.*;
import lombok.extern.slf4j.Slf4j;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Service;
import javax.annotation.PreDestroy;

/**
 * This class holds all SMPP configuration from application.yml
 * Example: application.smpp-config.system-id: "your-id"
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "application.smpp-config")
public class SmppConfigParameters {
    // SSH tunnel settings
    private String bastionHost;       // SSH server address
    private int bastionPort;          // SSH port (usually 22)
    private String bastionUser;       // SSH username
    private String privateKeyResourcePath; // Path to SSH private key
    
    // Timeout settings
    private int sshConnectionTimeoutMs;      // SSH connect timeout
    private int sshServerAliveIntervalSecs; // Keep SSH alive every X seconds
    private boolean smppHealthCheckEnabled; // Enable/disable health checks
    
    // List of SMPP servers to connect to
    private List<SmppServerConfig> servers = new ArrayList<>();
    
    // SMPP connection settings
    private int smppWindowSize;        // How many messages can be in-flight
    private String systemId;           // Your SMPP login ID
    private String systemPassword;     // Your SMPP password
    private int smppBindTimeoutMs;     // Time to wait for connection
    private int smppUnbindTimeoutMs;   // Time to wait when disconnecting
    private long smppSubmitTimeoutMs;  // Time to wait for SMS send response
    
    // Keep-alive settings (send ping messages)
    private int keepAliveInitialDelaySecs = 10; // Wait 10s before first ping
    private int keepAlivePeriodSecs = 30;       // Send ping every 30s
}

/**
 * Settings for each SMPP server
 */
@Data
public class SmppServerConfig {
    private String name;        // Server nickname (e.g., "server-1")
    private String remoteHost;  // Real SMPP server address
    private int remotePort;     // Real SMPP port (usually 2775)
    private int localPort;      // Local port after SSH tunnel (e.g., 10001)
    private int poolSize;       // How many connections to this server
}

// =============================================
// PART 2: SMPP CONNECTION - THE WORKHORSE
// =============================================

@Slf4j
public class SmppConnection {
    private final SMPPSession session;  // jSMPP library session
    private final SmppSessionConfiguration config; // Connection details
    private volatile boolean isBound = false; // Are we connected?

    /**
     * Create a new connection (but don't connect yet)
     */
    public SmppConnection(SmppSessionConfiguration config, int unbindTimeoutMs) {
        this.config = config;
        this.session = new SMPPSession();  // Create jSMPP session
    }

    /**
     * Connect to SMPP server
     * Throws exception if connection fails
     */
    public void open() throws Exception {
        if (isHealthy()) return; // Already connected? Skip
        
        try {
            // Connect and login to SMPP server
            session.connectAndBind(
                config.getHost(),           // Server address
                config.getPort(),           // Server port
                new BindParameter(
                    BindType.BIND_TX,       // TX = Transmitter only (send-only)
                    config.getSystemId(),   // Your username
                    config.getPassword(),   // Your password
                    "",                     // System type (optional)
                    TypeOfNumber.UNKNOWN,
                    NumberingPlanIndicator.UNKNOWN,
                    null
                ),
                config.getBindTimeoutMs()   // Timeout for connection
            );
            isBound = true; // Mark as connected
            log.info("Connected to SMPP server: {}:{}", config.getHost(), config.getPort());
        } catch (Exception e) {
            isBound = false; // Connection failed
            throw e;
        }
    }

    /**
     * Disconnect from SMPP server
     */
    public void close() {
        if (session != null && isBound) {
            try {
                session.unbindAndClose(5000); // Disconnect with 5s timeout
                log.info("Disconnected from SMPP server: {}:{}", config.getHost(), config.getPort());
            } catch (Exception e) {
                log.warn("Error disconnecting from SMPP server", e);
            } finally {
                isBound = false; // Mark as disconnected
            }
        }
    }

    /**
     * Check if connection is alive and working
     */
    public boolean isHealthy() {
        return session != null && isBound && session.getSessionState().isBound();
    }

    /**
     * Send ONE SMS message to ONE phone number
     * @param submit - SMS details (to, from, message)
     * @param timeoutMs - How long to wait for response
     * @param tunnelManager - SSH tunnel manager
     * @return Server's response
     */
    public SubmitSmResp sendSingle(SubmitSm submit, long timeoutMs, SshTunnelManager tunnelManager) throws Exception {
        boolean didRetry = false; // Track if we already retried once
        Exception lastException = null;

        do {
            try {
                if (!isHealthy()) {
                    throw new IllegalStateException("SMPP connection not healthy");
                }
                
                // Send the SMS using jSMPP
                return session.submitShortMessage(
                    submit.getServiceType(),
                    submit.getSourceAddrTon(),
                    submit.getSourceAddrNpi(),
                    submit.getSourceAddr(),
                    submit.getDestAddrTon(),
                    submit.getDestAddrNpi(),
                    submit.getDestAddress(),
                    submit.getEsmClass(),
                    submit.getProtocolId(),
                    submit.getPriorityFlag(),
                    submit.getScheduleDeliveryTime(),
                    submit.getValidityPeriod(),
                    submit.getRegisteredDelivery(),
                    submit.getReplaceIfPresentFlag(),
                    submit.getDataCoding(),
                    submit.getSmDefaultMsgId(),
                    submit.getShortMessage(),
                    timeoutMs
                );
            } catch (Exception ex) {
                lastException = ex; // Save error
                close(); // Close broken connection
                
                if (!didRetry) {
                    didRetry = true; // Mark that we'll retry
                    tunnelManager.ensureUp(); // Fix SSH tunnel if needed
                    open(); // Reconnect to SMPP server
                } else {
                    throw lastException; // Already retried, give up
                }
            }
        } while (didRetry);
        
        // Should never reach here
        throw new IllegalStateException("Unexpected error in send logic");
    }

    /**
     * Send ONE SMS message to MANY phone numbers at once
     * @param submitMulti - SMS details + list of phone numbers
     * @param timeoutMs - How long to wait
     * @param tunnelManager - SSH tunnel
     * @return Server's response with results for each number
     */
    public SubmitMultiResp sendMultiple(SubmitMulti submitMulti, long timeoutMs, SshTunnelManager tunnelManager) throws Exception {
        boolean didRetry = false;
        Exception lastException = null;

        do {
            try {
                if (!isHealthy()) throw new IllegalStateException("SMPP connection not healthy");
                
                // Convert phone numbers to jSMPP format
                DestinationAddress[] destinations = submitMulti.getDestAddresses().stream()
                    .map(addr -> new DestinationAddress(
                        new Address(addr.getTon(), addr.getNpi(), addr.getAddress())
                    ))
                    .toArray(DestinationAddress[]::new);
                
                // Send bulk SMS
                return session.submitMultiple(
                    submitMulti.getServiceType(),
                    submitMulti.getSourceAddrTon(),
                    submitMulti.getSourceAddrNpi(),
                    submitMulti.getSourceAddr(),
                    destinations, // All phone numbers
                    submitMulti.getEsmClass(),
                    submitMulti.getProtocolId(),
                    submitMulti.getPriorityFlag(),
                    submitMulti.getScheduleDeliveryTime(),
                    submitMulti.getValidityPeriod(),
                    submitMulti.getRegisteredDelivery(),
                    submitMulti.getReplaceIfPresentFlag(),
                    submitMulti.getDataCoding(),
                    submitMulti.getSmDefaultMsgId(),
                    submitMulti.getShortMessage(),
                    timeoutMs
                );
            } catch (Exception ex) {
                lastException = ex;
                close();
                
                if (!didRetry) {
                    didRetry = true;
                    tunnelManager.ensureUp();
                    open();
                } else {
                    throw lastException;
                }
            }
        } while (didRetry);
        
        throw new IllegalStateException("Unexpected error in bulk send logic");
    }

    /**
     * Send a "ping" to keep connection alive
     * SMPP servers may disconnect idle connections
     */
    public void enquireLink() {
        if (isHealthy()) {
            try {
                session.enquireLink(new EnquireLink(), 1000); // Ping with 1s timeout
            } catch (Exception e) {
                log.error("Ping failed: {}", e.getMessage());
                if (e.getMessage().contains("Not bound")) {
                    isBound = false; // Mark as disconnected
                }
            }
        }
    }
}

// =============================================
// PART 3: CONNECTION POOLING
// =============================================

/**
 * Factory to create new SMPP connections
 */
public interface PoolFactory {
    SmppConnection create() throws Exception;
}

/**
 * Pool of connections to ONE SMPP server
 * Like a "taxi stand" with multiple taxis (connections)
 */
@Slf4j
public class SmppConnectionPool {
    private final String serverName; // Which server this pool is for
    private final BlockingQueue<SmppConnection> pool; // Queue of available connections
    private final PoolFactory factory; // Factory to create new connections
    private final ScheduledExecutorService keepAliveScheduler; // Timer for pings

    /**
     * Create pool with N connections
     */
    public SmppConnectionPool(PoolFactory factory, int maxSize, String serverName, 
                             SmppConfigParameters config) throws Exception {
        this.pool = new LinkedBlockingQueue<>(maxSize);
        this.serverName = serverName;
        this.factory = factory;
        this.keepAliveScheduler = Executors.newSingleThreadScheduledExecutor();

        // Create all connections at startup
        for (int i = 0; i < maxSize; i++) {
            SmppConnection conn = factory.create();
            conn.open(); // Connect to SMPP server
            pool.offer(conn); // Add to pool
        }
        startKeepAliveTask(); // Start ping timer
    }

    /**
     * Start timer that pings all connections every X seconds
     */
    private void startKeepAliveTask() {
        keepAliveScheduler.scheduleAtFixedRate(() -> {
            log.debug("Sending pings to server: {}", serverName);
            for (SmppConnection conn : pool) {
                try {
                    if (conn.isHealthy()) {
                        conn.enquireLink(); // Send ping
                    }
                } catch (Exception e) {
                    log.error("Ping failed for server {}", serverName);
                }
            }
        }, 10, 30, TimeUnit.SECONDS); // Start in 10s, repeat every 30s
    }

    /**
     * Borrow/checkout a connection from the pool
     * Like taking a taxi from the taxi stand
     * @param timeout - How long to wait if no taxis available
     */
    public SmppConnection borrow(long timeout) throws InterruptedException {
        SmppConnection conn = pool.poll(timeout, TimeUnit.MILLISECONDS);
        if (conn == null) {
            throw new RuntimeException("All connections busy for server " + serverName);
        }
        
        // Check if taxi is broken
        if (!conn.isHealthy()) {
            conn.close(); // Discard broken connection
            try {
                conn = factory.create(); // Make new connection
                conn.open();
            } catch (Exception e) {
                throw new RuntimeException("Cannot fix broken connection", e);
            }
        }
        return conn; // Return working connection
    }

    /**
     * Return connection to pool after use
     * Like returning taxi to the stand
     */
    public void release(SmppConnection conn, SshTunnelManager tunnelManager) {
        if (conn.isHealthy()) {
            // Taxi still working? Put back in pool
            if (!pool.offer(conn)) {
                log.warn("Pool full, discarding connection");
                conn.close();
            }
        } else {
            // Taxi broken? Get a new one
            try {
                conn.close(); // Discard broken
                tunnelManager.ensureUp(); // Check SSH tunnel
                SmppConnection newConn = factory.create(); // Make new
                newConn.open();
                if (!pool.offer(newConn)) {
                    log.warn("Pool full, discarding new connection");
                    newConn.close();
                }
            } catch (Exception e) {
                log.error("Failed to replace broken connection", e);
            }
        }
    }

    /**
     * Shutdown pool - close all connections
     */
    public void shutdown() {
        keepAliveScheduler.shutdown(); // Stop ping timer
        for (SmppConnection conn : pool) {
            conn.close(); // Close all connections
        }
        pool.clear(); // Empty the pool
    }

    /**
     * Check if all connections in pool are healthy
     */
    public boolean isHealthy() {
        for (SmppConnection conn : pool) {
            if (!conn.isHealthy()) return false;
        }
        return !pool.isEmpty(); // Also false if pool is empty
    }

    public String getServerName() {
        return serverName;
    }
}

/**
 * Manages multiple pools (one per server)
 * Like managing multiple taxi stands in different locations
 */
@Slf4j
public class SmppPoolGroup {
    private final List<SmppConnectionPool> pools; // List of all pools
    private final AtomicInteger rrIndex = new AtomicInteger(0); // Round-robin counter

    public SmppPoolGroup(List<SmppConnectionPool> pools) {
        this.pools = pools;
    }

    /**
     * Get next pool index using round-robin
     * Example: 0,1,2,0,1,2,0,1,2...
     */
    public int nextPoolIndex() {
        return Math.floorMod(rrIndex.getAndIncrement(), size());
    }

    /**
     * Get order to try pools
     * Example: If 3 pools and next is 1, order = [1,2,0]
     */
    public int[] poolAttemptOrder() {
        int n = size();
        int start = nextPoolIndex();
        int[] order = new int[n];
        for (int i = 0; i < n; i++) {
            order[i] = (start + i) % n; // Wrap around
        }
        return order;
    }

    public SmppConnectionPool get(int idx) {
        return pools.get(idx);
    }

    public int size() {
        return pools.size();
    }

    /**
     * Shutdown all pools
     */
    public void shutdown() {
        pools.forEach(SmppConnectionPool::shutdown);
    }
}

// =============================================
// PART 4: MAIN MESSAGE SENDER
// =============================================

@Slf4j
@Service
public class SmppMessageSender {
    private final SshTunnelManager tunnelManager; // Manages SSH tunnel
    private final SmppPoolGroup poolGroup;       // All connection pools
    private final SmppConfigParameters config;   // Configuration

    /**
     * Constructor - sets up everything
     */
    public SmppMessageSender(SmppConfigParameters config) throws Exception {
        this.config = config;
        this.tunnelManager = new SshTunnelManager(config);
        this.tunnelManager.open(); // Start SSH tunnel

        List<SmppConnectionPool> pools = new ArrayList<>();
        
        // Create pool for each SMPP server
        for (SmppServerConfig server : config.getServers()) {
            SmppSessionConfiguration smppCfg = buildSessionConfig(server, config);
            
            // Factory to create connections to this server
            PoolFactory factory = () -> new SmppConnection(smppCfg, config.getSmppUnbindTimeoutMs());
            
            // Create pool with N connections
            pools.add(new SmppConnectionPool(
                factory, 
                server.getPoolSize(), 
                server.getName(), 
                config
            ));
        }
        
        this.poolGroup = new SmppPoolGroup(pools);
        log.info("Ready to send SMS via {} servers", pools.size());
    }

    /**
     * Send SMS to ONE phone number
     */
    public SmppSendResult sendSms(NotificationContext ctx, String phoneNumber, String shortCode) {
        return sendToNumbers(ctx, Collections.singletonList(phoneNumber), shortCode, false);
    }

    /**
     * Send same SMS to MANY phone numbers
     */
    public SmppSendResult sendBulkSms(NotificationContext ctx, List<String> phoneNumbers, String shortCode) {
        return sendToNumbers(ctx, phoneNumbers, shortCode, true);
    }

    /**
     * Main sending logic - tries all servers until one works
     */
    private SmppSendResult sendToNumbers(NotificationContext ctx, List<String> phoneNumbers, 
                                        String shortCode, boolean useBulkMode) {
        // Check if SMS sending is enabled
        if (!config.isSmppHealthCheckEnabled()) {
            throw new IllegalStateException("SMS sending is disabled");
        }
        
        // Get order to try servers (round-robin)
        int[] order = poolGroup.poolAttemptOrder();
        Exception lastError = null;
        
        // Try each server in order
        for (int idx : order) {
            SmppConnectionPool pool = poolGroup.get(idx);
            SmppConnection conn = null;
            try {
                // Get a connection from pool (wait up to 1 second)
                conn = pool.borrow(config.getSmppSubmitTimeoutMs());
                
                // Check SSH tunnel
                SmppSendResult tunnelCheck = ensureTunnelUp();
                if (tunnelCheck != null) return tunnelCheck;
                
                if (useBulkMode && phoneNumbers.size() > 1) {
                    // Send to multiple numbers
                    SubmitMulti submitMulti = buildSubmitMulti(ctx, phoneNumbers, shortCode);
                    SubmitMultiResp resp = conn.sendMultiple(submitMulti, config.getSmppSubmitTimeoutMs(), tunnelManager);
                    return new SmppSendResult(true, null, resp, null, pool.getServerName());
                } else {
                    // Send to single number
                    SubmitSm submit = buildSubmitSm(ctx, phoneNumbers.get(0), shortCode);
                    SubmitSmResp resp = conn.sendSingle(submit, config.getSmppSubmitTimeoutMs(), tunnelManager);
                    return new SmppSendResult(true, resp, null, null, pool.getServerName());
                }
            } catch (Exception ex) {
                // This server failed, try next one
                lastError = ex;
                log.error("Server {} failed: {}", pool.getServerName(), ex.getMessage());
            } finally {
                // Always return connection to pool
                if (conn != null) {
                    pool.release(conn, tunnelManager);
                }
            }
        }
        
        // All servers failed
        return new SmppSendResult(false, null, null, lastError, "All servers failed");
    }

    /**
     * Build SMS for ONE recipient
     */
    private SubmitSm buildSubmitSm(NotificationContext ctx, String phoneNumber, String shortCode) {
        SubmitSm submit = new SubmitSm();
        
        // Who the SMS is FROM
        submit.setSourceAddrTon(TypeOfNumber.INTERNATIONAL.value());
        submit.setSourceAddrNpi(NumberingPlanIndicator.ISDN.value());
        submit.setSourceAddr(shortCode); // Short code like "12345"
        
        // Who the SMS is TO
        submit.setDestAddrTon(TypeOfNumber.INTERNATIONAL.value());
        submit.setDestAddrNpi(NumberingPlanIndicator.ISDN.value());
        submit.setDestAddress(phoneNumber); // Phone number like "+1234567890"
        
        // Message content
        String message = ctx.getRenderingResponse();
        byte[] messageBytes = message.getBytes();
        
        if (messageBytes.length <= 255) {
            // Short message fits in standard field
            submit.setShortMessage(messageBytes);
        } else {
            // Long message needs special handling
            submit.setShortMessage(new byte[0]);
            submit.addOptionalParameter(new Tlv(SmppConstants.TAG_MESSAGE_PAYLOAD, messageBytes));
        }
        
        // Message encoding (GSM 7-bit, UTF-16, etc.)
        submit.setDataCoding((byte) ctx.getDataCoding());
        
        return submit;
    }

    /**
     * Build SMS for MULTIPLE recipients
     */
    private SubmitMulti buildSubmitMulti(NotificationContext ctx, List<String> phoneNumbers, String shortCode) {
        SubmitMulti submitMulti = new SubmitMulti();
        
        // Sender details
        submitMulti.setSourceAddr(shortCode);
        
        // Add all recipients
        List<DestinationAddress> destinations = new ArrayList<>();
        for (String phoneNumber : phoneNumbers) {
            destinations.add(new DestinationAddress(
                new Address(TypeOfNumber.INTERNATIONAL.value(), 
                          NumberingPlanIndicator.ISDN.value(), 
                          phoneNumber)
            ));
        }
        submitMulti.setDestAddresses(destinations);
        
        // Message content
        String message = ctx.getRenderingResponse();
        byte[] messageBytes = message.getBytes();
        
        if (messageBytes.length <= 255) {
            submitMulti.setShortMessage(messageBytes);
        } else {
            submitMulti.setShortMessage(new byte[0]);
            submitMulti.addOptionalParameter(new Tlv(SmppConstants.TAG_MESSAGE_PAYLOAD, messageBytes));
        }
        
        submitMulti.setDataCoding((byte) ctx.getDataCoding());
        
        return submitMulti;
    }

    /**
     * Build connection settings for a server
     */
    private SmppSessionConfiguration buildSessionConfig(SmppServerConfig server, SmppConfigParameters config) {
        SmppSessionConfiguration sessionConfig = new SmppSessionConfiguration();
        sessionConfig.setHost("127.0.0.1"); // SSH tunnel makes remote server appear local
        sessionConfig.setPort(server.getLocalPort()); // Local port after tunnel
        sessionConfig.setSystemId(config.getSystemId()); // Login username
        sessionConfig.setPassword(config.getSystemPassword()); // Login password
        sessionConfig.setBindTimeout(config.getSmppBindTimeoutMs());
        sessionConfig.setWindowSize(config.getSmppWindowSize()); // How many messages in flight
        return sessionConfig;
    }

    /**
     * Make sure SSH tunnel is working
     */
    private SmppSendResult ensureTunnelUp() {
        try {
            tunnelManager.ensureUp();
        } catch (Exception e) {
            log.error("SSH tunnel broken", e);
            return new SmppSendResult(false, null, null, e, "SSH tunnel broken");
        }
        return null;
    }

    /**
     * Clean shutdown when application stops
     */
    @PreDestroy
    public void shutdown() {
        poolGroup.shutdown(); // Close all connections
        tunnelManager.close(); // Close SSH tunnel
        log.info("SMS sender stopped");
    }
}

// =============================================
// PART 5: SUPPORTING CLASSES
// =============================================

/**
 * Result of sending SMS
 */
@Data
@AllArgsConstructor
public class SmppSendResult {
    private boolean success;           // Did it work?
    private SubmitSmResp submitSmResp; // Response for single SMS
    private SubmitMultiResp submitMultiResp; // Response for bulk SMS
    private Exception error;           // What went wrong (if any)
    private String attemptedServer;    // Which server we tried
}

/**
 * Simple session config
 */
@Data
public class SmppSessionConfiguration {
    private String host;
    private int port;
    private String systemId;
    private String password;
    private int bindTimeoutMs = 30000;
    private int windowSize = 10;
}

/**
 * SSH tunnel manager - creates secure tunnel to SMPP servers
 */
@Slf4j
public class SshTunnelManager {
    private final SmppConfigParameters config;
    private com.jcraft.jsch.Session session;
    
    public SshTunnelManager(SmppConfigParameters config) {
        this.config = config;
    }
    
    /**
     * Open SSH tunnel
     * Like building a secure bridge to SMPP servers
     */
    public synchronized void open() throws Exception {
        if (isOpen()) return; // Already open

        // Setup SSH connection
        com.jcraft.jsch.JSch jsch = new com.jcraft.jsch.JSch();
        jsch.addIdentity(config.getPrivateKeyResourcePath()); // SSH key
        
        session = jsch.getSession(
            config.getBastionUser(),
            config.getBastionHost(), 
            config.getBastionPort()
        );
        
        // SSH settings
        session.setConfig("StrictHostKeyChecking", "no"); // Don't check host key
        session.setConfig("TCPKeepAlive", "yes"); // Keep connection alive
        session.setConfig("ServerAliveInterval", 
            String.valueOf(config.getSshServerAliveIntervalSecs()));
        
        session.connect(config.getSshConnectionTimeoutMs());
        
        // Create port forwarding for each SMPP server
        // Example: Local port 10001 → Remote server:port
        for (SmppServerConfig server : config.getServers()) {
            session.setPortForwardingL(
                server.getLocalPort(),     // Local port (e.g., 10001)
                server.getRemoteHost(),    // Real SMPP server
                server.getRemotePort()     // Real SMPP port
            );
        }
        
        log.info("SSH tunnel ready");
    }
    
    public synchronized boolean isHealthy() {
        return session != null && session.isConnected();
    }
    
    public synchronized boolean isOpen() {
        return session != null && session.isConnected();
    }
    
    /**
     * Close SSH tunnel
     */
    public synchronized void close() {
        if (session != null) {
            session.disconnect();
            session = null;
            log.info("SSH tunnel closed");
        }
    }
    
    /**
     * Make sure tunnel is working, reconnect if needed
     */
    public synchronized void ensureUp() throws Exception {
        if (!isHealthy()) {
            log.warn("SSH tunnel broken, reconnecting...");
            close();
            open(); // Try to reconnect
        }
    }
}