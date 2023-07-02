package org.forgerock.openidconnect.oqs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.forgerock.json.jose.jwe.CompressionManager;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.jwt.Payload;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.util.encode.Base64url;
import org.openquantumsafe.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OqsSignedJWT extends SignedJwt {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");


    /**
     * Constructs a fresh, new SignedJwt from the given JwsHeader and JwtClaimsSet.
     * <p>
     * The specified private key will be used in the creation of the JWS signature.
     *
     * @param header The JwsHeader containing the header parameters of the JWS.
     * @param claimsSet The JwtClaimsSet containing the claims of the JWS.
     * @param signingHandler The SigningHandler instance used to sign the JWS.
     */
    public OqsSignedJWT(JwsHeader header, JwtClaimsSet claimsSet, SigningHandler signingHandler) {
        super(header, claimsSet, signingHandler);
        logger.error("Constructor 1 for OqsSignedJWT, extending SignedJwt");
    }

    public OqsSignedJWT(JwsHeader header, JwtClaimsSet claimsSet, byte[] signingInput, byte[] signature) {
        super(header, claimsSet, signingInput, signature);
        logger.error("Constructor 2 for OqsSignedJWT, extending SignedJwt");
    }

    
    @Override
    public String build() {
        JwsHeader header = getHeader();
        Payload payload = getPayload();

        String jwsHeader = header.build();
        String encodedHeader = Utils.base64urlEncode(jwsHeader);
        String jwsPayload = payload.build();
        String encodedPayload = Utils.base64urlEncode(jwsPayload);

        String signingInput = encodedHeader + "." + encodedPayload;

        // ----------------- OQS signature, dilithium (harcoded) ----------------------------
        logger.info("Creating Dilithium signature");

        String sig_name = "Dilithium2";
        // Check if key pair file has been created
        String rootPath = "/home/jacobo/tfm/openam-custom-server/config/security/keys/" + sig_name + "/";
        Path privateKeyPath = Paths.get(rootPath + "privateKey");
        Path publicKeyPath = Paths.get(rootPath + "publicKey");

        Signature signer = null;
        byte[] publicKey = null;

        if (Files.exists(privateKeyPath) && Files.isRegularFile(privateKeyPath)) {
            logger.info("Security key exists, try read from file...");
            byte[] privateKey;
            try {
                privateKey = Files.readAllBytes(privateKeyPath);
                signer = new Signature(sig_name, privateKey);
                publicKey = Files.readAllBytes(publicKeyPath);
            } catch (IOException e) {
                logger.error("Error while reading/creating security key files");
                e.printStackTrace();
            }

        } else {
            try {
                logger.error("Security key does not exist, creating new one");
                signer = new org.openquantumsafe.Signature(sig_name);
                publicKey = signer.generate_keypair();
                Files.createFile(publicKeyPath);
                Files.write(publicKeyPath, publicKey);
                Files.createFile(privateKeyPath);
                Files.write(privateKeyPath, signer.export_secret_key());
            } catch (IOException e) {
                logger.error("Error while reading/creating security key files: " + e.toString());
                e.printStackTrace();
            }
        }

        
        byte[] signature = signer.sign(signingInput.getBytes());
        signer.dispose_sig();
        
        String encodedSignature = Base64url.encode(signature);
        String idToken = signingInput + "." + encodedSignature;

        //TODO: Remove in final version

        /* Verifying signature */
        logger.info("Verifying signature");
        String [] id_token_splitted = idToken.split("\\.");
        String encodedHeaderVerifier = id_token_splitted[0];
        String encodedPayloadVerifier  = id_token_splitted[1];
        String encodedSignatureVerifier  = id_token_splitted[2];

        String headerPayload = encodedHeaderVerifier + "." +  encodedPayloadVerifier;

        Signature verifier = new Signature(sig_name);

        byte[] headerPayloadBytes = headerPayload.getBytes();

        byte[] signatureBytes = Base64url.decode(encodedSignatureVerifier);
        logger.info("signature lenght" + signatureBytes.length);
        logger.info("signinput lenght" + headerPayload.getBytes().length);
        logger.info("publicKey lenght" + publicKey.length);
        
        boolean is_valid = verifier.verify(headerPayloadBytes, signatureBytes, publicKey);
        logger.info("Is signature valid? " + is_valid);
        logger.info("id_token built:" + idToken);
        logger.info("id_token length:" + idToken.length());
        verifier.dispose_sig();

        /* Verify ended */
        return idToken;
    }

}