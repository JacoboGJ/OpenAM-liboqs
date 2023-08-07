package org.forgerock.oqs.json.jose.jws;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.openquantumsafe.Signature;

public class OqsSigningHandler {

    String algorithm;
    byte[] privateKey;
    byte[] publicKey;

    Signature signer;
    byte[] signature;
    boolean isValid;

    public OqsSigningHandler(OqsJwsAlgorithm algorithm) throws IOException {
        this.algorithm = algorithm.getAlgorithm();
        retrieveSecurityKeysFromFiles();
    }

    private void retrieveSecurityKeysFromFiles() throws IOException {
        String rootPath = "/home/jacobo/tfm/openam-custom-server/config/security/keys/" + algorithm + "/";
        Files.createDirectories(Paths.get(rootPath));
        Path privateKeyPath = Paths.get(rootPath + "privateKey");
        Path publicKeyPath = Paths.get(rootPath + "publicKey");

        if (Files.exists(privateKeyPath) && Files.isRegularFile(privateKeyPath)) {
            privateKey = Files.readAllBytes(privateKeyPath);
            publicKey = Files.readAllBytes(publicKeyPath);
        } else {
            signer = new Signature(algorithm);
            publicKey = signer.generate_keypair();
            privateKey = signer.export_secret_key();
            Files.createFile(publicKeyPath);
            Files.write(publicKeyPath, publicKey);
            Files.createFile(privateKeyPath);
            Files.write(privateKeyPath, privateKey);
            signer.dispose_sig();
        }
    }

    public byte[] sign(String data) {
        signer = new Signature(algorithm, privateKey);
        signature = signer.sign(data.getBytes());
        signer.dispose_sig();

        return signature;
    }

    public byte[] sign(byte[] data) {
        signer = new Signature(algorithm, privateKey);
        signature = signer.sign(data);
        signer.dispose_sig();

        return signature;
    }

    public boolean verify(byte[] data, byte[] signature) {
        signer = new Signature(algorithm);
        boolean isValid = signer.verify(data, signature, publicKey);
        signer.dispose_sig();
        
        return isValid;
    }
    
}

