import protocols.Applied;

import java.io.*;
import java.net.Socket;

public class CheckerProtocol {
    public static Applied checkAppliedProtocol(Socket socket) {
        try {
            InputStream in = socket.getInputStream();
            InputStreamReader inr = new InputStreamReader(in);
            BufferedReader br = new BufferedReader(inr);
            String line = "";
            if (br.ready())
                line = br.readLine();
            Applied temp = checkPOP3(line);
            if (temp == Applied.NONE)
                temp = checkIMAP(line);
            if (temp == Applied.NONE)
                temp = checkSMTP(line);
            if (temp == Applied.NONE)
                temp = checkHTTP(socket, br);
            br.close();
            return temp;
        } catch (IOException e) {
            return Applied.NONE;
        }
    }

    public static Applied checkAppliedProtocol(int port) {
        Applied temp = checkNTP(port);
        return temp != Applied.NONE
                ? temp
                : checkDNS(port);
    }

    private static Applied checkNTP(int port) {
        return port == 123
                ? Applied.NTP
                : Applied.NONE;
    }

    private static Applied checkDNS(int port) {
        return port == 53
                ? Applied.DNS
                : Applied.NONE;
    }

    private static Applied checkHTTP(Socket socket, BufferedReader br) {
        try {
            PrintWriter out = new PrintWriter(socket.getOutputStream(), false);
            out.print("GET / HTTP/1.0\r\nAccept: text/plain, text/html, text/*\r\n\r\n");
            out.flush();
            String line = br.readLine();
            if (line.contains("HTTP"))
                return Applied.HTTP;
            br.close();
        } catch (IOException ignored) {
            return Applied.NONE;
        }
        return Applied.NONE;
    }

    private static Applied checkPOP3(String line) {
        return checkMail(line, "+OK", Applied.POP3);
    }

    private static Applied checkSMTP(String line) {
        return checkMail(line, "220", Applied.SMTP);
    }

    private static Applied checkIMAP(String line) {
        return checkMail(line, " OK", Applied.IMAP);
    }

    private static Applied checkMail(String line, String characteristicPattern, Applied returnType) {
        if (line.contains(characteristicPattern))
            return returnType;
        return Applied.NONE;
    }
}
