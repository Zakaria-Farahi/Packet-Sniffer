package ma.enset.packetsniffer;

public class AlertHandler {


    private String title;
    private String message;
    public void triggerAlert(String title, String message) {
        // Print alert to console (can be expanded for more complex alert handling)
        this.title=title;
        this.message=message;

        // Optionally, you could trigger a GUI alert here or log the event
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
