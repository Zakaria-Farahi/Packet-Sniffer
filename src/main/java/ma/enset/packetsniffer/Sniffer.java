package ma.enset.packetsniffer;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class Sniffer extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(Sniffer.class.getResource("PacketSnifferView.fxml"));

        // Load the scene from FXML with appropriate dimensions
        Scene scene = new Scene(fxmlLoader.load());

        // Set the title to reflect the application purpose
        stage.setTitle("Packet Sniffer");
        stage.setScene(scene);
        stage.setMaximized(true);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}
