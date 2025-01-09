package ma.enset.packetsniffer;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SynFlood {
    private final AlertHandler alertHandler;

    private final Map<String, Integer> synFloodCount = new HashMap<>();
    private final Map<String, Long> lastPacketTime = new HashMap<>();
    private final Set<String> alertedIps = new HashSet<>(); // Ensemble pour garder les IP déjà alertées

    private static final int SYN_FLOOD_THRESHOLD = 10000; // Seuil de détection
    private static final long SYN_FLOOD_TIME_WINDOW = 1000; // Fenêtre de temps en millisecondes

    // Constructeur
    public SynFlood(AlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // Méthode pour analyser les paquets
    public void filterAndAnalyze(Packet packet) {
        if (packet.contains(TcpPacket.class) && packet.contains(IpV4Packet.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);

            // Vérifier si le paquet est un SYN sans ACK
            if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
                String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
                String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();  // Récupérer l'adresse IP de destination
                long currentTime = System.currentTimeMillis();

                // Mettre à jour le compteur pour l'IP source
                synFloodCount.put(srcIp, synFloodCount.getOrDefault(srcIp, 0) + 1);
                lastPacketTime.put(srcIp, currentTime);

                // Détection de SYN Flood
                if (synFloodCount.get(srcIp) >= SYN_FLOOD_THRESHOLD) {
                    // Ne déclencher l'alerte que si l'IP n'a pas encore été alertée
                    if (!alertedIps.contains(srcIp)) {
                        triggerSynFloodAlert(srcIp, dstIp, synFloodCount.get(srcIp));  // Passer l'adresse IP de destination
                        alertedIps.add(srcIp); // Ajouter l'IP à l'ensemble des alertes déjà envoyées
                    }
                    synFloodCount.put(srcIp, 0); // Réinitialiser le compteur après l'alerte
                }
            }

            // Nettoyage des IPs anciennes
            cleanUpOldEntries();
        }
    }


    // Déclenchement d'une alerte SYN Flood
    private void triggerSynFloodAlert(String srcIp, String dstIp, int synCount) {
        String alertTitle = "Attaque SYN Flood détectée";
        String alertMessage = "L'adresse IP " + srcIp + " a envoyé " + synCount + " paquets SYN sans réponse à l'adresse IP " + dstIp + ".";

        // Déclencher l'alerte via AlertHandler
        alertHandler.triggerAlert(alertTitle, alertMessage);
    }


    // Nettoyage des entrées expirées
    private void cleanUpOldEntries() {
        long currentTime = System.currentTimeMillis();
        synFloodCount.entrySet().removeIf(entry ->
                (currentTime - lastPacketTime.getOrDefault(entry.getKey(), currentTime)) > SYN_FLOOD_TIME_WINDOW
        );
    }
}
