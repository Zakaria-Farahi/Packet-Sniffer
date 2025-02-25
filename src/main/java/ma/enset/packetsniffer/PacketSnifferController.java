package ma.enset.packetsniffer;

import javafx.application.Platform;
import javafx.beans.property.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import ma.enset.packetsniffer.attacks.*;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

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
    private Tab alertsTab;

    @FXML
    private Tab snifferTab;

    @FXML
    private Tab activeUsersTab;

    @FXML
    public void goToAlertsTab() {
        mainTabPane.getSelectionModel().select(alertsTab); // Switch to the "Alerts" tab.
    }

    @FXML
    private Button snifferButton;

    @FXML
    public void goToSnifferTab() {
        mainTabPane.getSelectionModel().select(snifferTab); // Switch to the "Alerts" tab.
    }

    @FXML
    private Button activeUsersButton;

    @FXML
    public void goToUsersTab() {
        mainTabPane.getSelectionModel().select(activeUsersTab); // Switch to the "Alerts" tab.
    }



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

    private BooleanProperty isStartButtonDisabled = new SimpleBooleanProperty(false);
    private BooleanProperty isStopButtonDisabled = new SimpleBooleanProperty(true);;


    public boolean isStartButtonDisabled() {
        return isStartButtonDisabled.get();
    }

    public boolean getIsStopButtonDisabled() {
        return isStopButtonDisabled.get();
    }

    public void setStartButtonDisabled(boolean value) {
        isStartButtonDisabled.set(value);
    }

    public void setStopButtonDisabled(boolean value) {
        isStopButtonDisabled.set(value);
    }

    private final AlertHandler alertHandler = new AlertHandler();
    private final PacketCapture packetCapture = new PacketCapture();
    private final ObservableList<PacketData> packetList = FXCollections.observableArrayList();
    private final ObservableList<ActiveUser> activeUsersList = FXCollections.observableArrayList();
    private final Map<String, ActiveUser> activeUsersMap = new HashMap<>();
    private int packetCounter = 0;

    private SynFlood synFloodDetector;
    private LargeFileTransfer largeFileTransferDetector;

    @FXML
    private PieChart trafficPieChart;

    private Map<String, Integer> trafficTypeCounts = new HashMap<>();
    private PortScanDetection scanPort;

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
        largeFileTransferDetector = new LargeFileTransfer(alertHandler);
        scanPort= new PortScanDetection(alertHandler);

        // Configurer la table des paquets
        colNumber.setCellValueFactory(data -> {
            Property<Number> property = safeGetProperty(PacketData::numberProperty, data.getValue());
            return property instanceof IntegerProperty ? ((IntegerProperty) property).asObject() : new SimpleObjectProperty<>(null);
        });

        colLength.setCellValueFactory(data -> {
            Property<Number> property = safeGetProperty(PacketData::lengthProperty, data.getValue());
            return property instanceof IntegerProperty ? ((IntegerProperty) property).asObject() : new SimpleObjectProperty<>(null);
        });

        colTime.setCellValueFactory(data -> safeGetProperty(PacketData::timeProperty, data.getValue()));
        colSrcIP.setCellValueFactory(data -> safeGetProperty(PacketData::srcIPProperty, data.getValue()));
        colDstIP.setCellValueFactory(data -> safeGetProperty(PacketData::dstIPProperty, data.getValue()));
        colProtocol.setCellValueFactory(data -> safeGetProperty(PacketData::protocolProperty, data.getValue()));


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

        stopButton.disableProperty().bind(isStartButtonDisabled.not());
        startButton.disableProperty().bind(isStartButtonDisabled);
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
                setStopButtonDisabled(false);
                setStartButtonDisabled(true);
                if (packet == null) {
                    return;
                }

                PacketData data = PacketData.fromPacket(++packetCounter, packet);
                packetList.add(data);

                // Analyze traffic type and update the pie chart
                Platform.runLater(() -> {
                    String trafficType = getTrafficType(data); // Method to determine traffic type
                    trafficTypeCounts.put(trafficType, trafficTypeCounts.getOrDefault(trafficType, 0) + 1);
                    updateTrafficPieChart();
                });

                // Additional analysis (e.g., SYN flood detection)
                synFloodDetector.filterAndAnalyze(packet);
                scanPort.filterAndAnalyze(packet);
                largeFileTransferDetector.filterAndAnalyze(packet);

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
        setStartButtonDisabled(false);
        setStopButtonDisabled(true);

    }

    @FXML
    private void searchPackets() {
        String searchText = searchField.getText().toLowerCase();
        ObservableList<PacketData> filteredList = FXCollections.observableArrayList();

        for (PacketData packetData : packetList) {
            if (packetData != null && packetData.contains(searchText)) { // Check if packetData is not null
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


    private <T> Property<T> safeGetProperty(Function<PacketData, Property<T>> propertyGetter, PacketData data) {
        if (data != null) {
            return propertyGetter.apply(data);
        } else {
            return new SimpleObjectProperty<>(null);
        }
    }

    private String getTrafficType(PacketData data) {
        if (data == null) {
            return "unknown";
        }

        return data.protocolProperty().toString();
    }

    private void updateTrafficPieChart() {
        ObservableList<PieChart.Data> pieChartData = FXCollections.observableArrayList();
        for (Map.Entry<String, Integer> entry : trafficTypeCounts.entrySet()) {
            pieChartData.add(new PieChart.Data(entry.getKey(), entry.getValue()));
        }
        trafficPieChart.setData(pieChartData);
    }



}
