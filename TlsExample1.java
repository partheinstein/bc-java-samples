import java.io.*;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Vector;

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
	protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
	    System.out.println("get server signer credentials");
	    FileInputStream fis = new FileInputStream("x509-server-key-rsa-sign.pem");
	    PemReader p = new PemReader(new InputStreamReader(fis));
	    PemObject o = p.readPemObject();
	    p.close();

	    AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(o.getContent());

	    // read cert
	    p = new PemReader(new InputStreamReader(new FileInputStream("x509-server-rsa-sign.pem")));
	    o = p.readPemObject();
	    p.close();

	    TlsCertificate[] certChain = new TlsCertificate[]{getCrypto().createCertificate(o.getContent())};
	    Certificate certificate = new Certificate(certChain);
	    SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm) TlsUtils.getDefaultRSASignatureAlgorithms().elementAt(0);
	    return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context),
						      (BcTlsCrypto) getCrypto(),
						      privateKey,
						      certificate,
						      sigHashAlg);
	}
         
	@Override
	public CertificateRequest getCertificateRequest() throws IOException {
	    System.out.println("server getCertificateRequest");

	    Vector sigAndHashAlgs = new Vector(1);
	    sigAndHashAlgs.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
	    return new CertificateRequest(new short[]{ClientCertificateType.rsa_sign},
					  sigAndHashAlgs,
					  null);
					  
	}

	@Override
	public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
	    // TODO validate client cert
	    System.out.println("server recv client cert");
	}


        @Override
        public void run() {
            ServerSocket serverSocket = null;
            Socket socket = null;
            try {
                serverSocket = new ServerSocket(9999);
                socket = serverSocket.accept();
                TlsServerProtocol serverProtocol = new TlsServerProtocol(socket.getInputStream(),
									 socket.getOutputStream());
                System.out.println("server start handshake");
                serverProtocol.accept(this);
                System.out.println("server end handshake");

		int data = serverProtocol.getInputStream().read();
		System.out.println("server recv data: " + data);
		
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
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
		    throws IOException {
		    
                    System.out.println("notifyServerCertificate");
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
		    throws IOException {
		    
                    System.out.println("getClientCredentials");

                    // read private key
		    FileInputStream fis = new FileInputStream("x509-client-key-rsa.pem");
		    PemReader p = new PemReader(new InputStreamReader(fis));
                    PemObject o = p.readPemObject();
                    p.close();

                    AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(o.getContent());

                    // read cert
                    p = new PemReader(new InputStreamReader(new FileInputStream("x509-client-rsa.pem")));
                    o = p.readPemObject();
                    p.close();

		    TlsCertificate[] certChain = new TlsCertificate[]{getCrypto().createCertificate(o.getContent())};
		    Certificate certificate = new Certificate(certChain);
                    SignatureAndHashAlgorithm signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa);
                    
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
                TlsClientProtocol clientProtocol = new TlsClientProtocol(socket.getInputStream(),
									 socket.getOutputStream());
		System.out.println("client start handshake");
		clientProtocol.connect(this);
                System.out.println("client end handshake");

		// note that writing to socket.getOutputStream() will send
		// data in plaintext (i.e., it is not TLS application data record)
		
		System.out.println("client send data: " + 100);
		clientProtocol.getOutputStream().write(100);

		
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
