package ma.enset.packetsniffer;

public class Alerte {
    private final int num;
    private final String date;
    private final String title;
    private final String message;

    public Alerte(int num, String date, String title, String message) {
        this.num = num;
        this.date = date;
        this.title = title;
        this.message = message;
    }

    public int getNum() {
        return num;
    }

    public String getDate() {
        return date;
    }

    public String getTitle() {
        return title;
    }

    public String getMessage() {
        return message;
    }
}
