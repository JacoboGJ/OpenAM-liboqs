package org.forgerock.oqs.json.jose.jws;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.openquantumsafe.Signature;

public class OqsSigningHandler {

    String algorithmString;
    OqsJwsAlgorithm algorithm;
    byte[] privateKey;
    byte[] publicKey;

    Signature signer;
    byte[] signature;
    boolean isValid;

    public OqsSigningHandler(OqsJwsAlgorithm algorithm) throws IOException {
        this.algorithmString = algorithm.getAlgorithm();
        this.algorithm = algorithm;
        retrieveSecurityKeysFromFiles();
    }

    private void retrieveSecurityKeysFromFiles() throws IOException {

        String rootPath = "/home/jacobo/tfm/openam-custom-server/config/security/keys/" + algorithm.name() + "/";
        Files.createDirectories(Paths.get(rootPath));
        Path privateKeyPath = Paths.get(rootPath + "privateKey");
        Path publicKeyPath = Paths.get(rootPath + "publicKey");

        if (Files.exists(privateKeyPath) && Files.isRegularFile(privateKeyPath)) {
            privateKey = Files.readAllBytes(privateKeyPath);
            publicKey = Files.readAllBytes(publicKeyPath);
        } else {
            signer = new Signature(algorithmString);
            publicKey = signer.generate_keypair();
            privateKey = signer.export_secret_key();
            Files.createFile(publicKeyPath);
            Files.write(publicKeyPath, publicKey);
            Files.createFile(privateKeyPath);
            Files.write(privateKeyPath, privateKey);
            signer.dispose_sig();
        }
    }

    public byte[] sign(String data) throws NoSuchAlgorithmException {

        signer = new Signature(algorithmString, privateKey);
        // Perform SHA if required
        if(!"NONE".equals(algorithm.getMdAlgorithm())){
            MessageDigest digest = MessageDigest.getInstance(algorithm.getMdAlgorithm());
            byte[] encodedhash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            signature = signer.sign(encodedhash);
        } else {
            signature = signer.sign(data.getBytes());
        }

        signer.dispose_sig();
        return signature;
    }

    public byte[] sign(byte[] data) throws NoSuchAlgorithmException {
        signer = new Signature(algorithmString, privateKey);

        // Perform SHA if required
        if(!"NONE".equals(algorithm.getMdAlgorithm())){
            MessageDigest digest = MessageDigest.getInstance(algorithm.getMdAlgorithm());
            byte[] encodedhash = digest.digest(data);
            signature = signer.sign(encodedhash);
        } else {
            signature = signer.sign(data);
        }

        signer.dispose_sig();
        return signature;
    }

    public boolean verify(byte[] data, byte[] signature) {
        signer = new Signature(algorithmString);
        boolean isValid = signer.verify(data, signature, publicKey);
        signer.dispose_sig();
        
        return isValid;
    }
    
}

