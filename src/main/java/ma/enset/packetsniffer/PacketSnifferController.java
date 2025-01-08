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


    private final PacketCapture packetCapture = new PacketCapture();
    private final ObservableList<PacketData> packetList = FXCollections.observableArrayList();
    private final ObservableList<ActiveUser> activeUsersList = FXCollections.observableArrayList();
    private final Map<String, ActiveUser> activeUsersMap = new HashMap<>();
    private int packetCounter = 0;

    @FXML
    public void initialize() {
        try {
            List<PcapNetworkInterface> interfaces = packetCapture.getAllInterfaces();
            interfaceChoiceBox.setItems(FXCollections.observableArrayList(interfaces));
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Error loading interfaces: " + e.getMessage());
            alert.showAndWait();
        }

        // Configure packet table
        colNumber.setCellValueFactory(data -> data.getValue().numberProperty().asObject());
        colTime.setCellValueFactory(data -> data.getValue().timeProperty());
        colSrcIP.setCellValueFactory(data -> data.getValue().srcIPProperty());
        colDstIP.setCellValueFactory(data -> data.getValue().dstIPProperty());
        colProtocol.setCellValueFactory(data -> data.getValue().protocolProperty());
        colLength.setCellValueFactory(data -> data.getValue().lengthProperty().asObject());

        packetTableView.setItems(packetList);

        // Configure active users table
        colMacAddress.setCellValueFactory(new PropertyValueFactory<>("macAddress"));
        colIsActive.setCellValueFactory(new PropertyValueFactory<>("active"));

        // Handle Alerts Button
        alertsButton.setOnAction(event -> mainTabPane.getSelectionModel().select(alertsTab));

        // Handle Sniffer Button
        snifferButton.setOnAction(event -> mainTabPane.getSelectionModel().select(snifferTab));

        // Handle Active Users Button
        activeUsersButton.setOnAction(event -> mainTabPane.getSelectionModel().select(activeUsersTab));

        activeUserTableView.setItems(activeUsersList);
    }


    @FXML
    private void startCapture() {
        SynFlood packetFilter = new SynFlood();
        AlertHandler synFloodAlert=new AlertHandler();

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

                packetFilter.filterAndAnalyze(packet, synFloodAlert); // Utilisation de filterAndAnalyze

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
            // Check if it's an Ethernet packet
            if (packet.contains(org.pcap4j.packet.EthernetPacket.class)) {
                org.pcap4j.packet.EthernetPacket ethernetPacket = packet.get(org.pcap4j.packet.EthernetPacket.class);
                return ethernetPacket.getHeader().getSrcAddr().toString(); // Extract source MAC address
            }
        } catch (Exception e) {
            System.err.println("Error extracting MAC address: " + e.getMessage());
        }
        return "00:00:00:00:00:00"; // Fallback for non-Ethernet packets
    }

    private void blockUser(String macAddress) {
        if (macAddress == null || macAddress.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Invalid MAC Address.");
            alert.showAndWait();
            return;
        }

        // Simulated blocking logic
        Alert alert = new Alert(Alert.AlertType.INFORMATION, "User with MAC Address " + macAddress + " has been blocked.");
        alert.showAndWait();

        // TODO: Implement the real blocking logic, e.g., adding the MAC to a blacklist or network filtering.
        System.out.println("Blocking user with MAC: " + macAddress);
    }

}