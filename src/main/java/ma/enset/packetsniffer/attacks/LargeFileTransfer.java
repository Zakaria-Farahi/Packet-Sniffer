package ma.enset.packetsniffer.attacks;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class LargeFileTransfer {
    private final AlertHandler alertHandler;

    private final Map<String, Long> dataTransferred = new HashMap<>();
    private final Map<String, Long> lastPacketTime = new HashMap<>();
    private final Set<String> alertedSessions = new HashSet<>(); // Track sessions that have already been alerted

    private static final long LARGE_FILE_THRESHOLD = 10 * 1024 * 1024; // 10 MB threshold
    private static final long TIME_WINDOW = 5000; // 5 seconds

    // Constructor
    public LargeFileTransfer(AlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // Analyze packets for large file transfers
    public void filterAndAnalyze(Packet packet) {
        if (packet.contains(TcpPacket.class) && packet.contains(IpV4Packet.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);

            String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
            long currentTime = System.currentTimeMillis();

            // Calculate packet size
            int packetSize = tcpPacket.length();

            // Combine IPs to create a unique session identifier
            String sessionKey = srcIp + " -> " + dstIp;

            // Update data transferred for the session
            dataTransferred.put(sessionKey, dataTransferred.getOrDefault(sessionKey, 0L) + packetSize);
            lastPacketTime.put(sessionKey, currentTime);

            // Check if the session exceeds the large file transfer threshold
            if (dataTransferred.get(sessionKey) >= LARGE_FILE_THRESHOLD) {
                // Trigger alert only if the session has not already been alerted
                if (!alertedSessions.contains(sessionKey)) {
                    triggerLargeFileTransferAlert(srcIp, dstIp, dataTransferred.get(sessionKey));
                    alertedSessions.add(sessionKey); // Mark the session as alerted
                }
                dataTransferred.put(sessionKey, 0L); // Reset the counter after the alert
            }

            // Cleanup old sessions
            cleanUpOldEntries();
        }
    }

    // Trigger an alert for large file transfer
    private void triggerLargeFileTransferAlert(String srcIp, String dstIp, long dataSize) {
        String alertTitle = "Large File Transfer Detected";
        String alertMessage = "A large file transfer of " + (dataSize / (1024 * 1024)) +
                " MB was detected from " + srcIp + " to " + dstIp + ".";

        // Trigger the alert via AlertHandler
        alertHandler.triggerAlert(alertTitle, alertMessage);
    }

    // Cleanup old session entries
    private void cleanUpOldEntries() {
        long currentTime = System.currentTimeMillis();

        // Remove old entries from dataTransferred and lastPacketTime maps
        dataTransferred.entrySet().removeIf(entry ->
                (currentTime - lastPacketTime.getOrDefault(entry.getKey(), currentTime)) > TIME_WINDOW
        );

        // Remove old entries from alertedSessions
        alertedSessions.removeIf(sessionKey ->
                !lastPacketTime.containsKey(sessionKey) // Remove session if it's no longer in lastPacketTime
        );
    }
}
