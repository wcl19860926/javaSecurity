package com.study.sec.cert;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.SecureRandom;

public class HttpsUtils {

    public static final String PROTOCOL_HTTPS = "TLS";


    public static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream inputStream = new FileInputStream(keyStorePath);
        ks.load(inputStream, password.toCharArray());
        inputStream.close();
        return ks;

    }


    public static SSLSocketFactory getSSLSocketFactory(String password, String keyStorePath, String trustStorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        keyManagerFactory.init(keyStore, password.toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustStore = getKeyStore(trustStorePath, password);
        trustManagerFactory.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance(PROTOCOL_HTTPS);
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
        return sslContext.getSocketFactory();
    }


    public static URLConnection getConnection(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        return url.openConnection();
    }


}
