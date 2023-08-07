/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014-2016 ForgeRock AS.
 */

package org.forgerock.openidconnect;

import static org.forgerock.oauth2.core.Utils.isEmpty;
import static org.forgerock.openam.oauth2.OAuth2Constants.CoreTokenParams.AUDIT_TRACKING_ID;
import static org.forgerock.openam.oauth2.OAuth2Constants.JWTTokenParams.*;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.builders.SignedJwtBuilderImpl;
import org.forgerock.json.jose.jwe.EncryptionMethod;
import org.forgerock.json.jose.jwe.JweAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.oauth2.core.Token;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.audit.AuditConstants;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuthProblemException;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openidconnect.oqs.OqsSignedJWT;
import org.forgerock.oqs.json.jose.jws.OqsJwsAlgorithm;
import org.forgerock.oqs.json.jose.jws.OqsJwsAlgorithmType;
import org.forgerock.oqs.json.jose.jws.OqsSigningHandler;
import org.forgerock.oqs.json.jose.jws.OqsSignedJwt;
import org.restlet.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Models an OpenId Connect Token.
 *
 * @since 12.0.0
 */
public class OpenIdConnectToken extends JsonValue implements Token {
    private static final String KEY_ID_HEADER = "kid";
    private static final String ALGORITHM_HEADER = "alg";

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");
    private final JwtBuilderFactory jwtBuilderFactory = new JwtBuilderFactory();
    private final byte[] clientSecret;
    private final KeyPair signingKeyPair;
    private final Key encryptionKey;
    private final String signingAlgorithm;
    private final boolean isIDTokenEncryptionEnabled;
    private final String encryptionAlgorithm;
    private final String encryptionMethod;
    private final String signingKeyId;
    private final String encryptionKeyId;

    /**
     * Constructs a new OpenIdConnectToken.
     *
     * @param signingKeyId               The signing key id.
     * @param encryptionKeyId            The encryption key id.
     * @param clientSecret               The client's secret.
     * @param signingKeyPair             The token's signing key pair.
     * @param encryptionKey              The token's encryption key.
     * @param signingAlgorithm           The signing algorithm.
     * @param encryptionAlgorithm        The encryption algorithm.
     * @param encryptionMethod           The encryption method.
     * @param isIDTokenEncryptionEnabled {@code true} If ID token encryption is
     *                                   enabled.
     * @param iss                        The issuer.
     * @param sub                        The subject.
     * @param aud                        The audience.
     * @param azp                        The authorized party.
     * @param exp                        The expiry time.
     * @param iat                        The issued at time.
     * @param authTime                   The authenticated time.
     * @param nonce                      The nonce.
     * @param ops                        The ops.
     * @param atHash                     The at_hash.
     * @param cHash                      The c_hash.
     * @param acr                        The acr.
     * @param amr                        The amr.
     * @param auditTrackingId            The audit tracking ID.
     * @param realm                      The realm.
     */
    public OpenIdConnectToken(String signingKeyId, String encryptionKeyId, byte[] clientSecret, KeyPair signingKeyPair,
            Key encryptionKey, String signingAlgorithm, String encryptionAlgorithm, String encryptionMethod,
            boolean isIDTokenEncryptionEnabled, String iss, String sub, String aud, String azp, long exp, long iat,
            long authTime, String nonce, String ops, String atHash, String cHash, String acr, List<String> amr,
            String auditTrackingId, String realm) {
        super(new HashMap<String, Object>());
        this.clientSecret = clientSecret;
        this.signingAlgorithm = signingAlgorithm;
        this.isIDTokenEncryptionEnabled = isIDTokenEncryptionEnabled;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.encryptionMethod = encryptionMethod;
        this.signingKeyPair = signingKeyPair;
        this.encryptionKey = encryptionKey;
        this.signingKeyId = signingKeyId;
        this.encryptionKeyId = encryptionKeyId;
        setIss(iss);
        setSub(sub);
        setAud(aud);
        setAzp(azp);
        setExp(exp);
        setIat(iat);
        setAuthTime(authTime);
        setNonce(nonce);
        setOps(ops);
        setAtHash(atHash);
        setCHash(cHash);
        setAcr(acr);
        setAmr(amr);
        setTokenType(OAuth2Constants.JWTTokenParams.JWT_TOKEN);
        setTokenName(OAuth2Constants.JWTTokenParams.ID_TOKEN);
        set(AUDIT_TRACKING_ID, auditTrackingId);
        setRealm(realm);
    }

    public OpenIdConnectToken(JwtClaimsSet claims) {
        super(new HashMap<String, Object>());
        this.clientSecret = null;
        this.signingAlgorithm = null;
        this.isIDTokenEncryptionEnabled = false;
        this.encryptionAlgorithm = null;
        this.encryptionMethod = null;
        this.signingKeyPair = null;
        this.encryptionKey = null;
        this.signingKeyId = null;
        this.encryptionKeyId = null;
        setClaims(claims, ISS, SUB, AZP, NONCE, OPS, AT_HASH, C_HASH, ACR, AUDIT_TRACKING_ID, AUTH_TIME, AMR, REALM);
        setAud(CollectionUtils.getFirstItem(claims.getAudience()));
        setTokenType(OAuth2Constants.JWTTokenParams.JWT_TOKEN);
        setTokenName(OAuth2Constants.JWTTokenParams.ID_TOKEN);
    }

    protected void setClaims(JwtClaimsSet claims, String... keys) {
        for (String key : keys) {
            if (claims.isDefined(key)) {
                this.put(key, claims.get(key).getObject());
            }
        }
    }

    /**
     * Sets the realm.
     *
     * @param realm The realm.
     */
    private void setRealm(final String realm) {
        if (!isEmpty(realm)) {
            put(OAuth2Constants.CoreTokenParams.REALM, realm);
        }
    }

    /**
     * Sets a value on the OpenId Connect token if the value is not null or an empty
     * String.
     *
     * @param key   The key. Must not be {@code null}.
     * @param value The value.
     */
    private void set(String key, String value) {
        if (!isEmpty(value)) {
            put(key, value);
        }
    }

    /**
     * Sets the issuer.
     *
     * @param iss The issuer.
     */
    private void setIss(String iss) {
        set(OAuth2Constants.JWTTokenParams.ISS, iss);
    }

    /**
     * Sets the subject.
     *
     * @param sub The subject.
     */
    private void setSub(String sub) {
        set(OAuth2Constants.JWTTokenParams.SUB, sub);
    }

    /**
     * Sets the audience.
     *
     * @param aud The audience.
     */
    private void setAud(String aud) {
        set(OAuth2Constants.JWTTokenParams.AUD, aud);
    }

    /**
     * Sets the authorized party.
     *
     * @param azp The authorized party.
     */
    private void setAzp(String azp) {
        set(AZP, azp);
    }

    /**
     * Sets the expiry time in seconds.
     *
     * @param exp The expiry time.
     */
    private void setExp(long exp) {
        put(OAuth2Constants.JWTTokenParams.EXP, exp);
    }

    /**
     * Sets the issued at time in seconds.
     *
     * @param iat The issued at time.
     */
    private void setIat(long iat) {
        put(OAuth2Constants.JWTTokenParams.IAT, iat);
    }

    /**
     * Sets the authenticated time in seconds.
     *
     * @param authTime The authenticated time.
     */
    private void setAuthTime(long authTime) {
        put(OAuth2Constants.JWTTokenParams.AUTH_TIME, authTime);
    }

    /**
     * Sets the nonce.
     *
     * @param nonce The nonce.
     */
    private void setNonce(String nonce) {
        set(OAuth2Constants.JWTTokenParams.NONCE, nonce);
    }

    /**
     * Sets the ops.
     *
     * @param ops The ops.
     */
    private void setOps(String ops) {
        set(OAuth2Constants.JWTTokenParams.OPS, ops);
    }

    /**
     * Sets the at_hash.
     *
     * @param atHash The at_hash.
     */
    private void setAtHash(String atHash) {
        set(OAuth2Constants.JWTTokenParams.AT_HASH, atHash);
    }

    /**
     * Sets the c_hash.
     *
     * @param cHash The c_hash.
     */
    private void setCHash(String cHash) {
        set(OAuth2Constants.JWTTokenParams.C_HASH, cHash);
    }

    /**
     * Sets the acr.
     *
     * @param acr The acr.
     */
    private void setAcr(String acr) {
        set(OAuth2Constants.JWTTokenParams.ACR, acr);
    }

    /**
     * Sets the amr.
     *
     * @param amr The amr.
     */
    private void setAmr(List<String> amr) {
        put(OAuth2Constants.JWTTokenParams.AMR, amr);
    }

    /**
     * Sets the token's type.
     *
     * @param tokenType The token's type.
     */
    private void setTokenType(String tokenType) {
        set(OAuth2Constants.CoreTokenParams.TOKEN_TYPE, tokenType);
    }

    /**
     * Sets the token's name.
     *
     * @param tokenName The token's name.
     */
    private void setTokenName(String tokenName) {
        set(OAuth2Constants.CoreTokenParams.TOKEN_NAME, tokenName);
    }

    /**
     * {@inheritDoc}
     */
    public String getTokenId() throws ServerException {
        try {
            return createJwt().build();
        } catch (SignatureException e) {
            logger.error("Cant get JWT id", e);
            throw new ServerException("Cant get JWT id");
        }
    }

    /**
     * {@inheritDoc}
     */
    public String getTokenName() {
        return get(OAuth2Constants.CoreTokenParams.TOKEN_NAME).asString();
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, Object> toMap() throws ServerException {
        final Map<String, Object> tokenMap = new HashMap<String, Object>();
        try {
            tokenMap.put(OAuth2Constants.JWTTokenParams.ID_TOKEN, createJwt());
        } catch (SignatureException e) {
            logger.error("Cant sign JWT", e);
            throw new ServerException("Cant sign JWT");
        }
        return tokenMap;
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, Object> getTokenInfo() {
        return new HashMap<String, Object>();
    }

    /**
     * {@inheritDoc}
     */
    public JsonValue toJsonValue() {
        return this;
    }

    @Override
    public String getAuditTrackingId() {
        return get(AUDIT_TRACKING_ID).asString();
    }

    @Override
    public AuditConstants.TrackingIdKey getAuditTrackingIdKey() {
        return AuditConstants.TrackingIdKey.OIDC_ID_TOKEN;
    }

    /**
     * Signs the OpenId Connect token.
     *
     * @return A SignedJwt
     * @throws SignatureException If an error occurs with the signing of the OpenId
     *                            Connect token.
     */
    private Jwt createJwt() throws SignatureException {
        logger.error("OpenIdConnectToken.java - createJwt()");

        OqsJwsAlgorithm jwsAlgorithm = OqsJwsAlgorithm.valueOf(signingAlgorithm);
        if (isIDTokenEncryptionEnabled && (isEmpty(encryptionAlgorithm) || isEmpty(encryptionMethod)
                || encryptionKey == null)) {
            logger.info("ID Token Encryption not set. algorithm: {}, method: {}", encryptionAlgorithm,
                    encryptionMethod);
            throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(),
                    "ID Token Encryption not set. algorithm: " + encryptionAlgorithm + ", method: " + encryptionMethod);
        }
        SigningHandler signingHandler = getSigningHandler(jwsAlgorithm);

        JwtClaimsSet claimsSet = jwtBuilderFactory.claims().claims(asMap()).build();
        if (isIDTokenEncryptionEnabled) {
            logger.info("ID Token Encryption enabled. algorithm: {}, method: {}", encryptionAlgorithm,
                    encryptionMethod);
            return createEncryptedJwt(signingHandler, jwsAlgorithm, claimsSet);
        } else {
            return createSignedJwt(signingHandler, jwsAlgorithm, claimsSet);
        }
    }

    private SigningHandler getSigningHandler(OqsJwsAlgorithm jwsAlgorithm) {
        SigningHandler signingHandler;
        if (OqsJwsAlgorithmType.RSA.equals(jwsAlgorithm.getAlgorithmType())) {
            signingHandler = new SigningManager().newRsaSigningHandler(signingKeyPair.getPrivate());
        } else if (OqsJwsAlgorithmType.ECDSA.equals(jwsAlgorithm.getAlgorithmType())) {
            signingHandler = new SigningManager().newEcdsaSigningHandler((ECPrivateKey) signingKeyPair.getPrivate());
        } else if (OqsJwsAlgorithmType.PQ.equals(jwsAlgorithm.getAlgorithmType())) {
            signingHandler = null;
        } else {
            signingHandler = new SigningManager().newHmacSigningHandler(clientSecret);
        }
        return signingHandler;
    }

    private Jwt createEncryptedJwt(SigningHandler signingHandler, OqsJwsAlgorithm jwsAlgorithm,
            JwtClaimsSet claimsSet) {
        // As per http://openid.net/specs/openid-connect-core-1_0.html#SigningOrder, JWT
        // should be signed first and
        // then encrypted.
        return signedJwtBuilder(signingHandler, jwsAlgorithm, claimsSet).encrypt(encryptionKey).headers()
                .alg(JweAlgorithm.parseAlgorithm(encryptionAlgorithm))
                .enc(EncryptionMethod.parseMethod(encryptionMethod))
                .headerIfNotNull(KEY_ID_HEADER, encryptionKeyId)
                .done().asJwt();
    }

    private Jwt createSignedJwt(SigningHandler signingHandler, OqsJwsAlgorithm jwsAlgorithm, JwtClaimsSet claimsSet) {
        logger.error("OpenIdConnectToken.java - createSignedJwt()");
        if (OqsJwsAlgorithmType.PQ.equals(jwsAlgorithm.getAlgorithmType())) {
            logger.error("OpenIdConnectToken-createdSignedJwt: PQ token");
            OqsSigningHandler oqsSigningHandler;
            try {
                oqsSigningHandler = new OqsSigningHandler(jwsAlgorithm);
                return new org.forgerock.oqs.json.jose.jws.OqsSignedJwt(OqsJwsHeaderBuilder(),
                    claimsSet, oqsSigningHandler);
            } catch (IOException e) {
                logger.error("IOException: " + e.getMessage());
                e.printStackTrace();
                return null;
            } catch (Exception e) {
                logger.error("Exception: " + e.getMessage());
                e.printStackTrace();
                return null;
            }

        } else {
            logger.error("OpenIdConnectToken-createdSignedJwt: Not PQ token");
            return signedJwtBuilder(signingHandler, jwsAlgorithm, claimsSet).asJwt();
        }
    }

    private SignedJwtBuilderImpl signedJwtBuilder(SigningHandler signingHandler, OqsJwsAlgorithm jwsAlgorithm,
            JwtClaimsSet claimsSet) {
        return jwtBuilderFactory.jws(signingHandler).headers().alg(jwsAlgorithm)
                .headerIfNotNull(KEY_ID_HEADER, signingKeyId).done().claims(claimsSet);
    }

    private JwsHeader OqsJwsHeaderBuilder(){
        Map <String, Object> headersMap = new HashMap<String,Object>();
        headersMap.put(KEY_ID_HEADER, signingKeyId);
        headersMap.put(ALGORITHM_HEADER, signingAlgorithm);
        JwsHeader jwsHeader = new JwsHeader(headersMap);
        logger.error("Create OqsJwsHeaderBuilder: " + jwsHeader.build());
        return jwsHeader;
    }
}
