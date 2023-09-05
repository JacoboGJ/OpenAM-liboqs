package org.forgerock.oqs.json.jose.jws;

import org.forgerock.json.jose.jwt.Jwt;

import java.security.NoSuchAlgorithmException;

import org.forgerock.json.jose.jwe.CompressionManager;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.jwt.JwtHeader;
import org.forgerock.json.jose.jwt.Payload;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.util.encode.Base64url;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OqsSignedJwt implements Jwt, Payload {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    private final OqsSigningHandler signingHandler;

    private final JwsHeader header;
    private final Payload payload;

    private final byte[] signingInput;
    private final byte[] signature;

    /**
     * Constructs a fresh, new SignedJwt from the given JwsHeader and JwtClaimsSet.
     * <p>
     * The specified private key will be used in the creation of the JWS signature.
     *
     * @param header The JwsHeader containing the header parameters of the JWS.
     * @param claimsSet The JwtClaimsSet containing the claims of the JWS.
     * @param signingHandler The SigningHandler instance used to sign the JWS.
     */
    public OqsSignedJwt(JwsHeader header, JwtClaimsSet claimsSet, OqsSigningHandler signingHandler) {
        this.header = header;
        this.payload = claimsSet;
        this.signingHandler = signingHandler;

        this.signingInput = null;
        this.signature = null;
    }

    public OqsSignedJwt(JwsHeader header, JwtClaimsSet claimsSet, byte[] signingInput, byte[] signature) {
        this.header = header;
        this.payload = claimsSet;
        this.signingInput = signingInput;
        this.signature = signature;

        this.signingHandler = null;
    }
    
    @Override
    public String build() {

        String jwsHeader = header.build();
        String encodedHeader = Utils.base64urlEncode(jwsHeader);
        String jwsPayload = payload.build();
        String encodedPayload = Utils.base64urlEncode(jwsPayload);

        String signingInput = encodedHeader + "." + encodedPayload;

        byte[] signature;
        try {
            signature = signingHandler.sign(signingInput);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Exception while signing token. NoSuchAlgorithmException");
            e.printStackTrace();
            signature = null;
        }

        return signingInput + "." + Base64url.encode(signature);
    }

    @Override
    public JwtHeader getHeader() {
        return header;
    }

    @Override
    public JwtClaimsSet getClaimsSet() {
        return (JwtClaimsSet) payload;
    }

    protected Payload getPayload() {
        return payload;
    }

    public boolean verify(OqsSigningHandler signingHandler) {
        return signingHandler.verify(signingInput, signature);
    }

}