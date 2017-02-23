/*
 * AJPFuzzer - Utils.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC.
 */
package com.doyensec.ajpfuzzer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.sql.Timestamp;
import org.apache.commons.io.HexDump;
import com.doyensec.ajp13.AjpMessage;
import com.doyensec.ajp13.AjpReader;


public class Utils {

    protected static byte[] sendAndReceive(AJPFuzzer ajpsocket, byte[] data, String testCase, boolean verbose) throws UnsupportedEncodingException, IOException {
        if (verbose) dumpRequest(data, testCase);

        //The max packet size is 8 * 1024 getBytes (8K)
        byte[] buffReply = new byte[8192];
        int fullSize;

        DataOutputStream os = new DataOutputStream(ajpsocket.getSocket().getOutputStream());
        DataInputStream is = new DataInputStream(ajpsocket.getSocket().getInputStream());

        try {
            //Send
            os.write(data);
            os.flush();

            //Wait
            Thread.sleep(1200);

            //Receive. Be aware, we may receive multiple packets.
            while (is.available() > 0) {

                fullSize = is.read(buffReply);

                if (fullSize > 0) {

                    //Reduce size to actual received bytes
                    byte[] fullReply = new byte[fullSize];
                    System.arraycopy(buffReply, 0, fullReply, 0, fullReply.length);

                    //Iterate through all received bytes to extract response packets
                    ArrayList<Byte> replyBuffer = new ArrayList<>();

                    for (int pc = 0; pc < fullReply.length; pc++) {

                        //New AJP Response packet
                        if (pc + 1 < fullReply.length) {
                            if (fullReply[pc] == 'A' && fullReply[pc + 1] == 'B') {
                                if (!replyBuffer.isEmpty()) {
                                    if (verbose) dumpResponse(Utils.fromArrayListToArray(replyBuffer));
                                }
                                //Reset
                                replyBuffer = new ArrayList();
                            }
                        }
                        replyBuffer.add(fullReply[pc]);
                    }

                    if (!replyBuffer.isEmpty()) {
                        if (verbose) dumpResponse(Utils.fromArrayListToArray(replyBuffer));
                    }
                }
                //Wait
                Thread.sleep(1200);
            }
        } catch (IOException ex) {
            System.out.println("[!] Socket read error\n");

            //Re-establish a new socket connection
            ajpsocket.disconnect();
            ajpsocket.reconnect();

        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        
        return buffReply;
    }

    protected static void sendAndReceiveVerbose(AJPFuzzer ajpsocket, byte[] data, String testCase) throws UnsupportedEncodingException, IOException {
        sendAndReceive(ajpsocket, data, testCase, true);
    }
    
    private static void dumpRequest(byte[] data, String testCase) throws IOException {
        System.out.println("\n[*] Sending Test Case '" + testCase + "'");
        System.out.println("[*] " + new Timestamp(new Date().getTime()));
        System.out.println("\n");
        HexDump.dump(data, 0, System.out, 0);
        System.out.println("\n");
    }

    private static void dumpResponse(byte[] data) throws IOException {
        AjpMessage parsed = AjpReader.parseMessage(data);
        System.out.println("[*] Received message type '" + (parsed == null ? "Unknown" : parsed.getName()) + "'");
        System.out.println("[*] Received message description '" + (parsed == null ? "Unknown" : parsed.getDescription()) + "'");
        System.out.println("[*] " + new Timestamp(new Date().getTime()));
        System.out.println("\n");
        HexDump.dump(data, 0, System.out, 0);
        System.out.println("\n");
    }

    //Flip a random bit in a random byte from the input array
    protected static byte[] flipBit(byte[] data) {
        Random rand = new Random();
        int rN = rand.nextInt(data.length);
        int rB = rand.nextInt(8) + 1;
        data[rN] = (byte) (data[rN] ^ (1 << rB));
        return data;
    }

    //Randomly slice a byte array
    protected static byte[] sliceAll(byte[] data) {
        Random rand = new Random();
        int start = rand.nextInt(data.length);
        int stop = rand.nextInt(data.length);
        byte[] slice;
        if (start <= stop) {
            slice = Arrays.copyOfRange(data, start, stop);
        } else {
            slice = Arrays.copyOfRange(data, stop, start);
        }
        return slice;
    }

    //Randomly slice a byte array, always starting from index 0
    protected static byte[] sliceFromBegin(byte[] data) {
        Random rand = new Random();
        int stop = rand.nextInt(data.length);
        byte[] slice = Arrays.copyOfRange(data, 0, stop);
        return slice;
    }

    protected static boolean isWindows() {
        String OS = System.getProperty("os.name").toLowerCase();
        return (OS.contains("win"));
    }

    private static byte[] fromArrayListToArray(ArrayList myList) {
        byte[] bytesArray = new byte[myList.size()];
        for (int i = 0; i < myList.size(); i++) {
            bytesArray[i] = (byte) myList.get(i);
        }
        return bytesArray;
    }
}