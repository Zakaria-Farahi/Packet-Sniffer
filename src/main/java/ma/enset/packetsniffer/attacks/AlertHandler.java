package ma.enset.packetsniffer.attacks;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.text.SimpleDateFormat;
import java.util.Date;

public class AlertHandler {
    private final ObservableList<Alerte> alertList = FXCollections.observableArrayList();
    private int alertCounter = 1;

    public ObservableList<Alerte> getAlertList() {
        return alertList;
    }

    public void triggerAlert(String title, String message) {
        // Format date
        String date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // Ajouter l'alerte à la liste observable
        alertList.add(new Alerte(alertCounter++, date, title, message));
        System.out.println("Alerte détectée : " + title + " - " + message);
    }
}
