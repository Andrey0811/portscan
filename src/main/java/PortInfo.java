import protocols.Applied;
import protocols.Transport;

public class PortInfo {
    private final int port;
    private final boolean isOpen;
    private Transport transProt;
    private final Applied appProt;

    public PortInfo(int p, boolean b, Transport transport, Applied protocol) {
        port = p;
        isOpen = b;
        transProt = transport;
        appProt = protocol;
    }

    public PortInfo(int p) {
        this.port = p;
        this.isOpen = false;
        this.transProt = Transport.NONE;
        appProt = Applied.NONE;
    }

    public boolean giveStatus() {
        return this.isOpen;
    }

    public void setTransportLayer(Transport prot) {
        transProt = prot;
    }

    @Override
    public String toString() {
        StringBuilder temp = new StringBuilder()
                .append(port)
                .append(" ");
        if (transProt != Transport.NONE)
            temp.append(transProt).append(" ");
        if (appProt != Applied.NONE)
            temp.append(appProt).append(" ");
        return temp.toString();
    }
}
