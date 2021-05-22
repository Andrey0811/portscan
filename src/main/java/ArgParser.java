import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public class ArgParser {
    public static Options getParser() {
        Options options = new Options();

        Option host = new Option("h", "host",
                true, "connection to host");
        host.setRequired(true);
        options.addOption(host);

        Option tcp = new Option("t", "tcp",
                false, "scan tcp ports");
        tcp.setRequired(false);
        options.addOption(tcp);

        Option udp = new Option("u", "udp",
                false, "scan udp ports");
        udp.setRequired(false);
        options.addOption(udp);

        Option prot = new Option("a", "applied-protocols",
                false, "check applied protocols");
        prot.setRequired(false);
        options.addOption(prot);

        Option range = new Option("p", "ports",
                true, "range ports");
        range.setRequired(false);
        range.setArgs(2);
        range.setValueSeparator(' ');
        options.addOption(range);

        return options;
    }
}
