package ma.enset.packetsniffer;


import javafx.beans.property.*;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

import java.text.SimpleDateFormat;
import java.util.Date;

public class PacketData {

    private final IntegerProperty number;
    private final StringProperty time;
    private final StringProperty srcIP;
    private final StringProperty dstIP;
    private final StringProperty protocol;
    private final IntegerProperty length;
    private final StringProperty info;

    public PacketData(int number, String time, String srcIP, String dstIP, String protocol, int length, String info) {
        this.number = new SimpleIntegerProperty(number);
        this.time = new SimpleStringProperty(time);
        this.srcIP = new SimpleStringProperty(srcIP);
        this.dstIP = new SimpleStringProperty(dstIP);
        this.protocol = new SimpleStringProperty(protocol);
        this.length = new SimpleIntegerProperty(length);
        this.info = new SimpleStringProperty(info);
    }

    public static PacketData fromPacket(int packetNumber, Packet packet) {
        if (packet == null) {
            return null;
        }

        // Parse packet data (example: this will vary based on packet library's API)
        String time = new SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            String srcIP = ipV4Packet.getHeader().getSrcAddr().getHostAddress();  // Extract source IP
            String dstIP = ipV4Packet.getHeader().getDstAddr().getHostAddress();  // Extract destination IP
            String protocol = ipV4Packet.getHeader().getProtocol().name();  // Extract protocol
            int length = packet.length();
            String info = packet.toString();  // Extract additional information

            // Customize extraction logic based on your requirements
            return new PacketData(packetNumber, time, srcIP, dstIP, protocol, length, info);
        }
        if (packet.get(ArpPacket.class) != null) {
            String srcIP = packet.get(ArpPacket.class).getHeader().getSrcProtocolAddr().getHostAddress();
            String brodcast = packet.get(ArpPacket.class).getHeader().getDstProtocolAddr().getHostAddress();
            return new PacketData(packetNumber, time, srcIP, brodcast, "ARP", packet.length(), "ARP packet");
        }

        if (packet.get(IpV6Packet.class) != null) {
            // Handle IPv6 packets
            IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
            return new PacketData(packetNumber, time, ipv6Packet.getHeader().getSrcAddr().toString(),
                    ipv6Packet.getHeader().getDstAddr().toString(),
                    "IPv6", packet.length(), "IPv6 packet");
        }

        return null;
    }

    public IntegerProperty numberProperty() {
        return number;
    }

    public StringProperty timeProperty() {
        return time;
    }

    public StringProperty srcIPProperty() {
        return srcIP;
    }

    public StringProperty dstIPProperty() {
        return dstIP;
    }

    public StringProperty protocolProperty() {
        return protocol;
    }

    public IntegerProperty lengthProperty() {
        return length;
    }

    public StringProperty infoProperty() {
        return info;
    }

    public boolean contains(String searchText) {
        return srcIP.get().toLowerCase().contains(searchText) ||
                dstIP.get().toLowerCase().contains(searchText) ||
                protocol.get().toLowerCase().contains(searchText) ||
                info.get().toLowerCase().contains(searchText);
    }
}
