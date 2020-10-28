package com.study.sec.cert;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class KeyStoreUtils {


    /**
     * 加载KeyStore
     *
     * @param keyStoreFilePath
     * @param storePassword
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static KeyStore getKeyStore(String keyStoreFilePath, String storePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream inputStream = new FileInputStream(new File(keyStoreFilePath));
        keyStore.load(inputStream, storePassword.toCharArray());
        inputStream.close();
        return keyStore;
    }


    /**
     * 获取私钥
     * @param storePath
     * @param alias
     * @param storePassword
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws UnrecoverableKeyException
     */
    public Key getPrivateKey(String storePath, String alias, String storePassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException {
        KeyStore keyStore = getKeyStore(storePath, storePassword);
        return keyStore.getKey(alias, storePassword.toCharArray());
    }


    public Signature getCertification(String storePath, String alias, String storePassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException {
        KeyStore keyStore = getKeyStore(storePath, storePassword);
        //如果我们想获取数据签名算法， 只能先能过别名，获取证书，再通过证书获取签名算法
        X509Certificate x509C =  (X509Certificate)keyStore.getCertificate(alias);
        Signature  signature  = Signature.getInstance(x509C.getSigAlgName());
        return  signature;
    }
}
