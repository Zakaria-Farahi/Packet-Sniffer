package ma.enset.packetsniffer;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.*;

public class SynFlood {

    private final List<Packet> tcpPackets = new ArrayList<>();
    private final Map<String, TcpPacket> synPacketsByIp = new HashMap<>();
    private final Map<String, Long> lastPacketTime = new HashMap<>();
    private final Map<String, Integer> synFloodCount = new HashMap<>();

    private static final int SYN_FLOOD_THRESHOLD = 100; // 100 SYN packets per second
    private static final long SYN_FLOOD_TIME_WINDOW = 1000; // 1 second window
    private static final long SYN_WAIT_TIME = 3000; // 3 seconds to receive ACK

    // Méthode pour filtrer et analyser les paquets
    public void filterAndAnalyze(Packet packet, AlertHandler alertHandler) {
        if (packet.contains(TcpPacket.class)) {
            tcpPackets.add(packet); // Add TCP packets for IP display
        }

        if (packet.contains(TcpPacket.class) && packet.contains(IpV4Packet.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);

            // Vérifier si le paquet est un SYN
            if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
                String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
                String key = srcIp + ":" + tcpPacket.getHeader().getSrcPort().valueAsInt() + "->" + tcpPacket.getHeader().getDstPort().valueAsInt();
                synPacketsByIp.put(key, tcpPacket);
                lastPacketTime.put(srcIp, System.currentTimeMillis());

                // Mettre à jour le comptage des paquets SYN
                updateSYNFloodCount(srcIp);
            }

            // Vérifier si le paquet est un ACK
            if (tcpPacket.getHeader().getAck() && tcpPacket.getHeader().getSyn()) {
                String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
                String key = dstIp + ":" + tcpPacket.getHeader().getDstPort().valueAsInt() + "->" + tcpPacket.getHeader().getSrcPort().valueAsInt();
                synPacketsByIp.remove(key);
            }

            // Détection des attaques SYN Flood
            detectSYNFlood(synFloodCount, alertHandler);
        }

        // Nettoyage des paquets SYN expirés (pas d'ACK dans le délai)
        removeExpiredSYNPackets();
    }

    // Met à jour le comptage des paquets SYN Flood
    private void updateSYNFloodCount(String ip) {
        long currentTime = System.currentTimeMillis();
        long lastTime = lastPacketTime.getOrDefault(ip, currentTime);

        if (currentTime - lastTime <= SYN_FLOOD_TIME_WINDOW) {
            synFloodCount.put(ip, synFloodCount.getOrDefault(ip, 0) + 1);
        } else {
            synFloodCount.put(ip, 1); // reset count if time window expired
        }
    }

    // Retirer les paquets SYN expirés qui n'ont pas reçu d'ACK dans le délai
    private void removeExpiredSYNPackets() {
        long currentTime = System.currentTimeMillis();
        Iterator<Map.Entry<String, TcpPacket>> iterator = synPacketsByIp.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, TcpPacket> entry = iterator.next();
            String srcIp = entry.getKey().split(":")[0];
            long lastTime = lastPacketTime.getOrDefault(srcIp, currentTime);

            if (currentTime - lastTime > SYN_WAIT_TIME) {
                iterator.remove(); // Retirer les paquets SYN non confirmés après le délai
                synFloodCount.put(srcIp, 0); // Réinitialiser le comptage pour cette IP
            }
        }
    }

    // Détection des attaques SYN Flood
    public void detectSYNFlood(Map<String, Integer> synFloodCount, AlertHandler alertHandler) {
        boolean synFloodDetected = false;

        for (Map.Entry<String, Integer> entry : synFloodCount.entrySet()) {
            if (entry.getValue() >= SYN_FLOOD_THRESHOLD) {
                alertHandler.triggerAlert("SYN Flood Detected", "The IP " + entry.getKey() + " has sent too many SYN packets without response.");
                synFloodDetected = true;
            }
        }

        if (!synFloodDetected) {
            System.out.println("\nAucune attaque SYN Flood détectée pour l'instant.");
        }
    }

    // Affichage des paquets TCP par IP
    public void displayTcpPacketsByIp() {
        Map<String, Integer> ipCounts = new HashMap<>();
        for (Packet packet : tcpPackets) {
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                ipCounts.put(srcIp, ipCounts.getOrDefault(srcIp, 0) + 1);
            }
        }

        System.out.println("=== Paquets TCP par adresse IP ===");
        for (Map.Entry<String, Integer> entry : ipCounts.entrySet()) {
            System.out.println("IP Source: " + entry.getKey() + ", Nombre de paquets: " + entry.getValue());
        }
    }

    // Affichage des paquets SYN sans réponse
    public void displayUnansweredSYN() {
        System.out.println("\n=== Paquets SYN sans réponse ===");
        for (String key : synPacketsByIp.keySet()) {
            System.out.println("SYN non répondu : " + key);
        }
    }
}
