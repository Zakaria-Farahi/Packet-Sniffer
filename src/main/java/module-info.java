module ma.enset.packetsniffer {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.pcap4j.core;
    requires java.logging;

    opens ma.enset.packetsniffer to javafx.fxml;
    exports ma.enset.packetsniffer;
}