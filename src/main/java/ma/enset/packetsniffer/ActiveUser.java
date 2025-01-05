package ma.enset.packetsniffer;

import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;

public class ActiveUser {
    private final SimpleStringProperty macAddress;
    private final SimpleBooleanProperty active;

    public ActiveUser(String macAddress, boolean isActive) {
        this.macAddress = new SimpleStringProperty(macAddress);
        this.active = new SimpleBooleanProperty(isActive);
    }

    public String getMacAddress() {
        return macAddress.get();
    }

    public boolean isActive() {
        return active.get();
    }

    public void setActive(boolean isActive) {
        active.set(isActive);
    }
}
