package ma.enset.packetsniffer;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PacketSnifferController {

    @FXML
    private ChoiceBox<PcapNetworkInterface> interfaceChoiceBox;

    @FXML
    private Button startButton;

    @FXML
    private Button stopButton;

    @FXML
    private TextField searchField;

    @FXML
    private TableView<PacketData> packetTableView;

    @FXML
    private TableColumn<PacketData, Integer> colNumber;

    @FXML
    private TableColumn<PacketData, String> colTime;

    @FXML
    private TableColumn<PacketData, String> colSrcIP;

    @FXML
    private TableColumn<PacketData, String> colDstIP;

    @FXML
    private TableColumn<PacketData, String> colProtocol;

    @FXML
    private TableColumn<PacketData, Integer> colLength;

    // Active Users TableView
    @FXML
    private TableView<ActiveUser> activeUserTableView;

    @FXML
    private TableColumn<ActiveUser, String> colMacAddress;

    @FXML
    private TableColumn<ActiveUser, Boolean> colIsActive;

    @FXML
    private TabPane mainTabPane;

    @FXML
    private Button alertsButton;

    @FXML
    private Button snifferButton;

    @FXML
    private Button activeUsersButton;

    @FXML
    private Tab alertsTab;

    @FXML
    private Tab snifferTab;

    @FXML
    private Tab activeUsersTab;

    @FXML
    private TableView<Alerte> alertTable;

    @FXML
    private TableColumn<Alerte, Integer> colNum;

    @FXML
    private TableColumn<Alerte, String> colDate;

    @FXML
    private TableColumn<Alerte, String> colTitle;

    @FXML
    private TableColumn<Alerte, String> colMessage;

    private final AlertHandler alertHandler = new AlertHandler();
    private final PacketCapture packetCapture = new PacketCapture();
    private final ObservableList<PacketData> packetList = FXCollections.observableArrayList();
    private final ObservableList<ActiveUser> activeUsersList = FXCollections.observableArrayList();
    private final Map<String, ActiveUser> activeUsersMap = new HashMap<>();
    private int packetCounter = 0;

    private SynFlood synFloodDetector;

    @FXML
    public void initialize() {
        try {
            // Charger les interfaces réseau
            List<PcapNetworkInterface> interfaces = packetCapture.getAllInterfaces();
            interfaceChoiceBox.setItems(FXCollections.observableArrayList(interfaces));
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Erreur lors du chargement des interfaces : " + e.getMessage());
            alert.showAndWait();
        }

        // Initialisation de SynFlood
        synFloodDetector = new SynFlood(alertHandler);

        // Configurer la table des paquets
        colNumber.setCellValueFactory(data -> data.getValue().numberProperty().asObject());
        colTime.setCellValueFactory(data -> data.getValue().timeProperty());
        colSrcIP.setCellValueFactory(data -> data.getValue().srcIPProperty());
        colDstIP.setCellValueFactory(data -> data.getValue().dstIPProperty());
        colProtocol.setCellValueFactory(data -> data.getValue().protocolProperty());
        colLength.setCellValueFactory(data -> data.getValue().lengthProperty().asObject());

        packetTableView.setItems(packetList);

        // Configurer la table des utilisateurs actifs
        colMacAddress.setCellValueFactory(new PropertyValueFactory<>("macAddress"));
        colIsActive.setCellValueFactory(new PropertyValueFactory<>("active"));
        activeUserTableView.setItems(activeUsersList);

        // Configurer la table des alertes
        colNum.setCellValueFactory(new PropertyValueFactory<>("num"));
        colDate.setCellValueFactory(new PropertyValueFactory<>("date"));
        colTitle.setCellValueFactory(new PropertyValueFactory<>("title"));
        colMessage.setCellValueFactory(new PropertyValueFactory<>("message"));

        // Lier les données des alertes
        alertTable.setItems(alertHandler.getAlertList());

        // Gérer le bouton pour afficher l'onglet des alertes
        alertsButton.setOnAction(event -> mainTabPane.getSelectionModel().select(alertsTab));

        // Gérer le bouton pour afficher l'onglet du sniffer
        snifferButton.setOnAction(event -> mainTabPane.getSelectionModel().select(snifferTab));

        // Gérer le bouton pour afficher l'onglet des utilisateurs actifs
        activeUsersButton.setOnAction(event -> mainTabPane.getSelectionModel().select(activeUsersTab));
    }

    @FXML
    private void startCapture() {
        PcapNetworkInterface selectedInterface = interfaceChoiceBox.getValue();
        if (selectedInterface == null) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Please select a network interface.");
            alert.showAndWait();
            return;
        }

        packetCapture.selectInterface(selectedInterface);

        try {
            packetCapture.startCapture(packet -> {
                PacketData data = PacketData.fromPacket(++packetCounter, packet);
                packetList.add(data);

                // Analyse du paquet et détection SYN Flood
                synFloodDetector.filterAndAnalyze(packet);

                updateActiveUsers(packet);
            });
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Error starting capture: " + e.getMessage());
            alert.showAndWait();
        }
    }

    @FXML
    private void stopCapture() {
        packetCapture.stopCapture();
    }

    @FXML
    private void searchPackets() {
        String searchText = searchField.getText().toLowerCase();
        ObservableList<PacketData> filteredList = FXCollections.observableArrayList();

        for (PacketData packetData : packetList) {
            if (packetData.contains(searchText)) {
                filteredList.add(packetData);
            }
        }
        packetTableView.setItems(filteredList);
    }

    private void updateActiveUsers(Packet packet) {
        String macAddress = extractMacAddress(packet);
        if (macAddress != null && !activeUsersMap.containsKey(macAddress)) {
            ActiveUser newUser = new ActiveUser(macAddress, true);
            activeUsersMap.put(macAddress, newUser);
            activeUsersList.add(newUser);
        }
    }

    private String extractMacAddress(Packet packet) {
        if (packet == null) {
            return "00:00:00:00:00:00";
        }
        try {
            if (packet.contains(org.pcap4j.packet.EthernetPacket.class)) {
                org.pcap4j.packet.EthernetPacket ethernetPacket = packet.get(org.pcap4j.packet.EthernetPacket.class);
                return ethernetPacket.getHeader().getSrcAddr().toString();
            }
        } catch (Exception e) {
            System.err.println("Error extracting MAC address: " + e.getMessage());
        }
        return "00:00:00:00:00:00";
    }

    private void blockUser(String macAddress) {
        if (macAddress == null || macAddress.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Invalid MAC Address.");
            alert.showAndWait();
            return;
        }

        // Logique simulée de blocage
        Alert alert = new Alert(Alert.AlertType.INFORMATION, "User with MAC Address " + macAddress + " has been blocked.");
        alert.showAndWait();

        System.out.println("Blocking user with MAC: " + macAddress);
    }
}
