package ma.enset.packetsniffer.attacks;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PortScanDetection {
    private final AlertHandler alertHandler;

    private final Map<String, Set<Integer>> scannedPortsByIp = new HashMap<>();
    private final Map<String, Long> lastPacketTime = new HashMap<>();
    private final Set<String> alertedIps = new HashSet<>();
    private final Set<String> alertedTargets = new HashSet<>(); // Nouvel ensemble pour IP cibles alertées

    private static final int PORT_SCAN_THRESHOLD = 20; // Nombre de ports différents
    private static final long TIME_WINDOW = 3000; // Fenêtre de temps en millisecondes

    // Constructeur
    public PortScanDetection(AlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // Méthode pour analyser les paquets
    public void filterAndAnalyze(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
            String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
            int dstPort = getDestinationPort(packet);

            // Vérifier si l'IP source a déjà été ciblée
            if (alertedTargets.contains(srcIp)) {
                return; // Ignorer les alertes provenant d'IP déjà signalées comme cibles
            }

            if (dstPort != -1) {
                long currentTime = System.currentTimeMillis();

                // Ajouter le port scanné pour l'IP source
                scannedPortsByIp.putIfAbsent(srcIp, new HashSet<>());
                scannedPortsByIp.get(srcIp).add(dstPort);
                lastPacketTime.put(srcIp, currentTime);

                // Vérifier si le seuil est dépassé
                if (scannedPortsByIp.get(srcIp).size() >= PORT_SCAN_THRESHOLD) {
                    if (!alertedIps.contains(srcIp)) {
                        triggerPortScanAlert(srcIp, dstIp, scannedPortsByIp.get(srcIp).size());
                        alertedIps.add(srcIp); // Ajouter l'IP source aux alertes déclenchées
                        alertedTargets.add(dstIp); // Ajouter l'IP cible comme adresse surveillée
                    }
                    scannedPortsByIp.get(srcIp).clear(); // Réinitialiser les ports scannés
                }
            }

            // Nettoyer les entrées anciennes
            cleanUpOldEntries();
        }
    }

    // Récupérer le port de destination à partir d'un paquet TCP ou UDP
    private int getDestinationPort(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            return tcpPacket.getHeader().getDstPort().valueAsInt();
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            return udpPacket.getHeader().getDstPort().valueAsInt();
        }
        return -1; // Pas de port valide
    }

    // Déclenchement d'une alerte de scan de ports
    private void triggerPortScanAlert(String srcIp, String dstIp, int portCount) {
        String alertTitle = "Scan de ports détecté";
        String alertMessage = "L'adresse IP " + srcIp + " a scanné " + portCount + " ports différents sur " + dstIp + ".";

        // Déclencher l'alerte via AlertHandler
        alertHandler.triggerAlert(alertTitle, alertMessage);
        System.out.println("Alert detected: " + srcIp + " -> " + dstIp);
    }

    // Nettoyage des entrées expirées
    private void cleanUpOldEntries() {
        long currentTime = System.currentTimeMillis();
        scannedPortsByIp.entrySet().removeIf(entry ->
                (currentTime - lastPacketTime.getOrDefault(entry.getKey(), currentTime)) > TIME_WINDOW
        );
    }
}
