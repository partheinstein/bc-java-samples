import java.io.*;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetSocketAddress;
import java.security.SecureRandom;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;

public class TlsExample1 {

    public static class Server extends DefaultTlsServer implements Runnable {

        public Server() {
            super(new BcTlsCrypto(new SecureRandom()));
        }
         
        
        @Override
        public void run() {
            ServerSocket serverSocket = null;
            Socket socket = null;
            try {
                serverSocket = new ServerSocket(9999);
                socket = serverSocket.accept();
                TlsServerProtocol serverProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
                System.out.println("server start handshake");
                serverProtocol.accept(this);
                System.out.println("server end handshake");
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (serverSocket != null) {
                    try {serverSocket.close();} catch (IOException e){}
                }
                if (socket != null) {
                    try {socket.close();} catch (IOException e){}
                }
            }
            
        }
    }

    public static class Client extends DefaultTlsClient implements Runnable {

        public Client() {
            super(new BcTlsCrypto(new SecureRandom()));
        }
        
        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                    System.out.println("notifyServerCertificate");
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    System.out.println("getClientCredentials");

                    // read private key
                    PemReader p = new PemReader(new InputStreamReader(new FileInputStream("x509-client-key-rsa.pem")));
                    PemObject o = p.readPemObject();
                    p.close();

                    AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(o.getContent());

                    // read cert
                    p = new PemReader(new InputStreamReader(new FileInputStream("x509-client-key-rsa.pem")));
                    o = p.readPemObject();
                    p.close();

                    Certificate certificate = new Certificate(new TlsCertificate[]{getCrypto().createCertificate(o.getContent())});

                    SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
                    for (int i = 0; i <  certificateRequest.getSupportedSignatureAlgorithms().size(); ++i) {
                        SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm) supportedSignatureAlgorithms.elementAt(i);
                        if (alg.getSignature() == SignatureAlgorithm.rsa) {
                            // Just grab the first one we find
                            signatureAndHashAlgorithm = alg;
                            break;
                        }
                    }
                    
                    return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context),
                                                              (BcTlsCrypto) getCrypto(),
                                                              privateKey,
                                                              certificate,
                                                              signatureAndHashAlgorithm);
                }
            };
        }

        
        @Override
        public void run() {
            Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress("localhost", 9999));
                TlsClientProtocol clientProtocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
                clientProtocol.connect(this);
                System.out.println("client start handshake");
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (socket != null) {
                    try {socket.close();} catch (IOException e){}
                }
            }

        }
    }

    
    public static void main(String[] args) throws Exception {
        Thread serverThread = new Thread(new Server());
        serverThread.start();
        new Client().run();

    }
}
