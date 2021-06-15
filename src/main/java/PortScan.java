import protocols.Applied;
import protocols.Transport;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

public class PortScan {
    public static Future<PortInfo> portIsOpen(final ExecutorService es, String ip, int port,
                                              boolean tcp, boolean udp, boolean checkProtocols) {
        return es.submit(() -> {
            PortInfo portInfo = tryToConnect(ip, port, 100, tcp, udp, checkProtocols);
            if (portInfo == null)
                portInfo = new PortInfo(port);

            return portInfo;
        });
    }

    private static PortInfo tryToConnect(String ip, int port, int timeout,
                                         boolean tcp, boolean udp, boolean checkProtocols) {
        if (tcp)
            return checkTCP(ip, port, timeout, checkProtocols);
        if (udp)
            return checkUDP(ip, port, timeout, checkProtocols);

        PortInfo temp = checkTCP(ip, port, timeout, checkProtocols);
        if (temp == null)
            temp = checkUDP(ip, port, timeout, checkProtocols);
//        else
//            if (Transport.NONE != checkSSL(ip, port, timeout))
//                temp.setTransportLayer(Transport.SSL);
            return temp;
    }

    private static PortInfo checkTCP(String ip , int port, int timeout, boolean checkProtocols) {
        try {
            Socket soc = new Socket();
            soc.connect(new InetSocketAddress(ip,port), timeout);
            Applied protocol = Applied.NONE;
            if (checkProtocols)
                protocol = CheckerProtocol.checkAppliedProtocol(soc);
            soc.close();
            return new PortInfo(port, true, Transport.TCP, protocol);
        }
        catch (Exception e) {
            return null;
        }
    }

    private static PortInfo checkUDP(String ip , int port, int timeout, boolean checkProtocols) {
        DatagramSocket ds;
        byte[] buff = new byte[128];
        try {
            ds = new DatagramSocket();
            DatagramPacket dp = new DatagramPacket(buff,buff.length);
            ds.setSoTimeout(timeout);
            ds.connect(new InetSocketAddress(ip, port));
            ds.send(dp);
            ds.isConnected();

            dp = new DatagramPacket(buff,buff.length);
            ds.receive(dp);
            ds.close();

            Applied protocol = Applied.NONE;
            if (checkProtocols)
                protocol = CheckerProtocol.checkAppliedProtocol(port);
            return new PortInfo(port, true, Transport.UDP, protocol);
        } catch (IOException e){
            return null;
        }
    }

    private static Transport checkSSL(String ip , int port, int timeout) {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{ new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) { }

                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }};

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket();
            sslSocket.connect(new InetSocketAddress(ip, port), timeout);
            sslSocket.startHandshake();
            javax.security.cert.X509Certificate[] certificates = sslSocket.getSession().getPeerCertificateChain();
            Date expiration = certificates[0].getNotAfter();
            sslSocket.close();

            return Transport.SSL;
        } catch (Exception ex) {
            return Transport.NONE;
        }
    }

    public static String getIp(String url) {
        final Pattern IPV4_PATTERN =
                Pattern.compile("^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$");
        final Pattern IPV6_STD_PATTERN =
                Pattern.compile("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
        final Pattern IPV6_HEX_COMPRESSED_PATTERN =
                Pattern.compile("^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$");
        if (IPV4_PATTERN.matcher(url).matches()
                || IPV6_STD_PATTERN.matcher(url).matches()
                || IPV6_HEX_COMPRESSED_PATTERN.matcher(url).matches())
            return url;

        if(!url.startsWith("http://") || !url.startsWith("https://") || !url.startsWith("www.")
                || !url.startsWith("wss://") || !url.startsWith("ws://"))
            url = "http://".concat(url);

        InetAddress addr = null;
        try {
            addr = InetAddress.getByName(new URL(url).getHost());
        } catch (UnknownHostException | MalformedURLException e) {
            System.err.println(e);
            System.exit(1);
        }
        return addr.getHostAddress();
    }
}
