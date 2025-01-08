package ma.enset.packetsniffer;

import ma.enset.packetsniffer.PacketCapture;
import ma.enset.packetsniffer.SynFlood;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

import java.util.*;

public class Test {
    public static void main(String[] args) {
        try {
            PacketCapture packetCapture = new PacketCapture();
            SynFlood packetFilter = new SynFlood();
            Scanner scanner = new Scanner(System.in);
            List<Packet> capturedPackets = new ArrayList<>();

            // === Étape 1 : Lister les interfaces réseau disponibles ===
            List<PcapNetworkInterface> interfaces = packetCapture.getAllInterfaces();
            if (interfaces.isEmpty()) {
                System.out.println("Aucune interface réseau détectée.");
                return;
            }

            System.out.println("=== Interfaces réseau disponibles ===");
            for (int i = 0; i < interfaces.size(); i++) {
                System.out.println((i + 1) + ". " + interfaces.get(i).getName() + " - " + interfaces.get(i).getDescription());
            }

            // === Étape 2 : Sélectionner une interface ===
            System.out.print("Sélectionnez une interface (par numéro) : ");
            int choice = scanner.nextInt();
            if (choice < 1 || choice > interfaces.size()) {
                System.out.println("Numéro invalide.");
                return;
            }
            PcapNetworkInterface selectedInterface = interfaces.get(choice - 1);
            packetCapture.selectInterface(selectedInterface);

            // === Étape 3 : Menu interactif ===
            boolean running = true;
            boolean capturing = false;
            Thread captureThread = null;

            while (running) {
                System.out.println("\n=== Menu ===");
                System.out.println("1. Démarrer la capture");
                System.out.println("2. Arrêter la capture");
                System.out.println("3. Afficher tous les paquets capturés");
                System.out.println("4. Afficher les paquets SYN sans réponse (SYN sans ACK)");
                System.out.println("5. Vérifier les attaques SYN Flood en temps réel");
                System.out.println("6. Quitter");
                System.out.print("Choisissez une option : ");
                int menuChoice = scanner.nextInt();

                switch (menuChoice) {
                    case 1:
                        if (capturing) {
                            System.out.println("La capture est déjà en cours.");
                        } else {
                            System.out.println("Démarrage de la capture sur l'interface : " + selectedInterface.getName());
                            captureThread = new Thread(() -> {
                                try {
                                    packetCapture.startCapture(packet -> {
                                        synchronized (capturedPackets) {
                                            capturedPackets.add(packet);
                                        }
                                        packetFilter.filterAndAnalyze(packet, new AlertHandler()); // Utilisation de filterAndAnalyze
                                    });
                                } catch (Exception e) {
                                    System.err.println("Erreur lors de la capture : " + e.getMessage());
                                }
                            });
                            captureThread.start();
                            capturing = true;
                        }
                        break;
                    case 2:
                        if (capturing) {
                            packetCapture.stopCapture();
                            if (captureThread != null) {
                                captureThread.interrupt(); // Arrête le thread de capture
                            }
                            capturing = false;
                            System.out.println("Capture arrêtée.");
                        } else {
                            System.out.println("Aucune capture en cours.");
                        }
                        break;
                    case 3:
                        displayCapturedPackets(capturedPackets);
                        break;
                    case 4:
                        packetFilter.displayUnansweredSYN();
                        break;
                    case 5:
                        packetFilter.detectSYNFlood(new HashMap<>(), new AlertHandler()); // Vérification des attaques SYN Flood
                        break;
                    case 6:
                        if (capturing) {
                            System.out.println("Veuillez arrêter la capture avant de quitter.");
                        } else {
                            running = false;
                        }
                        break;
                    default:
                        System.out.println("Option invalide.");
                }
            }

            System.out.println("Programme terminé.");

        } catch (PcapNativeException e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }

    // Fonction pour afficher tous les paquets capturés
    private static void displayCapturedPackets(List<Packet> capturedPackets) {
        synchronized (capturedPackets) {
            if (capturedPackets.isEmpty()) {
                System.out.println("\nAucun paquet capturé pour l'instant.");
            } else {
                System.out.println("\n=== Paquets Capturés ===");
                for (int i = 0; i < capturedPackets.size(); i++) {
                    System.out.println((i + 1) + ". " + capturedPackets.get(i));
                }
            }
        }
    }
}
