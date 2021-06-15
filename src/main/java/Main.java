import org.apache.commons.cli.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Main {
    public static void main(String[] args) throws ExecutionException, InterruptedException {
//        StopWatch stopWatch = new StopWatch();
        Options options = ArgParser.getParser();
        CommandLine cmd = null;

        try {
            cmd = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            new HelpFormatter().printHelp("PortScan", options);
            System.exit(1);
        }

        boolean tcp = cmd.hasOption("tcp");
        boolean udp = cmd.hasOption("udp");
        boolean prot = cmd.hasOption("applied-protocols");
        String[] range = cmd.getOptionValues("ports");
        String url = cmd.getOptionValue("host");

        System.out.println("Port Scanner\n");
        int start = Integer.parseInt(range[0]);
        int end = Integer.parseInt(range[1]);

//        stopWatch.start();
        String ip = PortScan.getIp(url);

        System.out.println("Scanning ports for ip: " + ip + " (" + url + ")");
        System.out.println("\nOpen ports: ");

        final ExecutorService es = Executors.newFixedThreadPool(20);
        final List<Future<PortInfo>> futures = new ArrayList<>() ;

        for(int i = start ; i <= end ; i++ )
            futures.add(PortScan.portIsOpen(es , ip , i, tcp, udp, prot)) ;
        es.shutdown();
//        stopWatch.stop();

        int countOpenPorts = 0 ;
        for(Future<PortInfo> f : futures)
            if(f.get().giveStatus()) {
                System.out.println(f.get().toString());
                countOpenPorts++;
            }

        System.out.println("\nTotal " + countOpenPorts + " ports open");
//        System.out.println("Done scan " + (end - start + 1) + " ports in " +
//                String.format("%.5f", (stopWatch.getTime() / 1000.0) / 60) + " min");
    }
}