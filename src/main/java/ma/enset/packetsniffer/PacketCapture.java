package ma.enset.packetsniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PacketCapture {

    private static final Logger LOGGER = Logger.getLogger(PacketCapture.class.getName());
    private PcapHandle handle;
    private PcapNetworkInterface selectedInterface;
    private final List<Packet> allPackets = new ArrayList<>();
    private Thread captureThread; // Keep a reference to the capture thread


    // Fetch all available network interfaces
    public List<PcapNetworkInterface> getAllInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    // Set the selected network interface
    public void selectInterface(PcapNetworkInterface pcapNetworkInterface) {
        this.selectedInterface = pcapNetworkInterface;
        LOGGER.info("Selected interface: " + pcapNetworkInterface.getName());
    }

    // Start capturing packets
    public void startCapture(PacketHandler callback) throws PcapNativeException {
        if (selectedInterface == null) {
            throw new IllegalStateException("No network interface selected.");
        }

        try {
            handle = selectedInterface.openLive(
                    65536, // Snapshot length
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, // Promiscuous mode
                    100 // Timeout in milliseconds
            );

            LOGGER.info("Started capturing on interface: " + selectedInterface.getName());

            // Start a new thread for packet capture
            captureThread = new Thread(() -> {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        Packet packet = handle.getNextPacket();
                        if (packet != null) {
                            synchronized (allPackets) {
                                allPackets.add(packet);
                            }
                            callback.handlePacket(packet);
                        }
                    }
                } catch (NotOpenException e) {
                    LOGGER.log(Level.SEVERE, "Packet handle not open.", e);
                }
            });

            captureThread.start();
        } catch (PcapNativeException e) {
            LOGGER.log(Level.SEVERE, "Error opening interface: " + selectedInterface.getName(), e);
            throw e;
        }
    }

    public void stopCapture() {
        if (captureThread != null && captureThread.isAlive()) {
            captureThread.interrupt(); // Interrupt the capture thread
            try {
                captureThread.join(); // Wait for the thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // Restore the interrupted status
                LOGGER.log(Level.WARNING, "Interrupted while waiting for capture thread to stop.", e);
            }
        }

        if (handle != null && handle.isOpen()) {
            handle.close(); // Safely close the handle
            LOGGER.info("Packet capture stopped.");
        }
    }

    // Get the list of all captured packets
    public List<Packet> getAllPackets() {
        synchronized (allPackets) {
            return new ArrayList<>(allPackets);
        }
    }

    // Functional interface for packet handling
    @FunctionalInterface
    public interface PacketHandler {
        void handlePacket(Packet packet);
    }
}