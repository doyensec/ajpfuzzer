/*
 * AJPFuzzer - AJPFuzzer.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC.
 */
package com.doyensec.ajpfuzzer;

import asg.cliche.Command;
import asg.cliche.Param;
import asg.cliche.Shell;
import asg.cliche.ShellDependent;
import asg.cliche.ShellFactory;
import asg.cliche.ShellManageable;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import org.apache.commons.io.input.TeeInputStream;
import org.apache.commons.io.output.TeeOutputStream;
import com.doyensec.ajp13.AjpMessage;
import com.doyensec.ajp13.AjpReader;
import com.doyensec.ajp13.CPingMessage;
import com.doyensec.ajp13.CPongMessage;

public class AJPFuzzer implements ShellDependent, ShellManageable {

    private final String version = "0.6";
    private Shell shell;
    private String host;
    private int port = 0;
    private Socket socket;
    private static FileOutputStream fos;
    private static TeeOutputStream myOut;
    private static TeeOutputStream myErr;
    private static TeeInputStream myIn;
    private static PrintStream psOut;
    private static PrintStream psErr;

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public Socket getSocket() {
        return socket;
    }

    public void setSocket(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void cliSetShell(Shell theShell) {
        this.shell = theShell;
    }

    public Shell cliGetShell() {
        return shell;
    }

    @Command(description = "Connect to a remote AJP13 service", name = "connect", abbrev = "cn")
    public void connect(@Param(name = "host", description = "AJP13 host") String host, @Param(name = "port", description = "AJP13 TCP port") int port) throws IOException {
        setHost(host);
        setPort(port);
        try {
            System.out.println("[*] Connecting to " + host + ":" + port);
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), 2000);
            socket.setSoTimeout(8000);
        } catch (IOException e) {
            System.out.println("[!] Connection error\n");
            System.exit(-1);
        }
        ShellFactory.createSubshell(host + ":" + port, shell, "Connected to the remote AJP13 service", new AJPTestCases(this)).commandLoop();
    }

    @Command(description = "Disconnect from a remote AJP13 service", name = "disconnect", abbrev = "dn")
    public void disconnect() {
        if (socket != null && !socket.isClosed()) {
            System.out.println("[*] Disconnecting...");
            try {
                socket.close();
            } catch (IOException ex) {
                System.out.println("[!] Disconnection error\n");
                System.exit(-1);
            }
        } else {
            System.out.println("[!] Disconnected\n");
        }
    }
    
    @Command(description = "Disconnect and quit AJPFuzzer", name = "quit", abbrev = "quit")
    public void quit() {
        this.cliLeaveLoop(); //Exit all
    }

    @Command(description = "Reconnect to the remote AJP13 service", name = "reconnect", abbrev = "rc")
    public void reconnect() {
        if (host != null && port != 0) {
            System.out.println("[*] Reconnecting...");
            try {
                System.out.println("[*] Connecting to " + host + ":" + port);
                socket = new Socket();
                socket.connect(new InetSocketAddress(host, port), 2000);
                socket.setSoTimeout(8000);
            } catch (IOException ex) {
                System.out.println("[!] Connection error\n");
                System.exit(-1);
            }
        } else {
            System.out.println("[!] You must connect first\n");
        }
    }

    @Command(description = "Status of the connection to the remote AJP13 service", name = "status", abbrev = "sta")
    public void status() throws IOException {
        if (socket != null && !socket.isClosed()) {
            //Sending AJP's CPing as heartbeat
            AjpMessage msg = new CPingMessage();
            byte[] reply = Utils.sendAndReceive(this, msg.getBytes(), "(10) cping", false);
            AjpMessage ajpReply = AjpReader.parseMessage(reply);
            if (ajpReply instanceof CPongMessage) {
                System.out.println("[*] Connected\n");
            } else {
                System.out.println("[!] Disconnected\n");
            }
        } else {
            System.out.println("[!] Disconnected\n");
        }
    }

    public static void main(String[] args) throws IOException {
        //Initialize logging
        try {
            fos = new FileOutputStream("AJPFuzzer_" + InetAddress.getLocalHost().getHostName() + "_" + System.nanoTime() + ".log");
            myOut = new TeeOutputStream(System.out, fos);
            myErr = new TeeOutputStream(System.err, fos);
            myIn = new TeeInputStream(System.in, myOut);
            psOut = new PrintStream(myOut);
            psErr = new PrintStream(myErr);
            System.setOut(psOut);
            System.setErr(psErr);
            System.setIn(myIn);
        } catch (UnknownHostException | FileNotFoundException e) {
            System.out.println("[!] Logging setup error\n");
        }

        //Start the fuzzer
        AJPFuzzer myFuzzer = new AJPFuzzer();
        myFuzzer.banner();
        Shell myShell = ShellFactory.createConsoleShell("AJPFuzzer", "", new AJPFuzzer());
        myFuzzer.cliSetShell(myShell);
        myShell.commandLoop();
    }

    @Override
    public void cliEnterLoop() {
        //do nothing
    }

    @Override
    public void cliLeaveLoop() {
        if (socket != null && !socket.isClosed()) {
            disconnect();
        }
        try {
            fos.close();
            myOut.close();
            myErr.close();
            myIn.close();
            psOut.close();
            psErr.close();
        } catch (IOException ex) {
            System.out.println("[!] Stream close error\n");
        }
    }

    private void banner() {
        System.out.println(".: AJPFuzzer v" + version + " - Doyensec.com :.");
        System.out.println("-----------------------------------");
    }
}
