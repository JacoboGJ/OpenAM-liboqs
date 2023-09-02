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

package org.forgerock.openam.utils;

import java.security.AccessController;
import java.security.KeyPair;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.oqs.json.jose.jws.OqsJwsAlgorithm;
import org.forgerock.oqs.json.jose.jws.OqsJwsAlgorithmType;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.configuration.MapValueParser;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

/**
 * Provides access to any OpenAM settings.
 *
 * @since 12.0.0
 */
public class OpenAMSettingsImpl implements OpenAMSettings {
    private static final MapValueParser MAP_VALUE_PARSER = new MapValueParser();

    //private final Debug logger = Debug.getInstance("amSMS");
    private final Debug logger = Debug.getInstance("OAuth2Provider");
    private final String serviceName;
    private final String serviceVersion;
    private  AMKeyProvider amKeyProvider;

    /**
     * Constructs a new OpenAMSettingsImpl.
     *
     * @param serviceName The service name.
     * @param serviceVersion The service version.
     */
    @Inject
    public OpenAMSettingsImpl(@Assisted("serviceName") String serviceName,
            @Assisted("serviceVersion") String serviceVersion) {
        this.serviceName = serviceName;
        this.serviceVersion = serviceVersion;
    }

    /**
     * {@inheritDoc}
     */
    public Set<String> getSetting(String realm, String attributeName) throws SSOException, SMSException {
        final ServiceConfig serviceConfig = getServiceConfig(realm);
        final Map<String, Set<String>> attributes = serviceConfig.getAttributes();
        return attributes.get(attributeName);
    }

    public boolean hasConfig(String realm) throws SSOException, SMSException {
        return getServiceConfig(realm).exists();
    }

    private ServiceConfig getServiceConfig(String realm) throws SMSException, SSOException {
        final SSOToken token = AccessController.doPrivileged(AdminTokenAction.getInstance());
        final ServiceConfigManager serviceConfigManager = new ServiceConfigManager(token, serviceName, serviceVersion);
        return serviceConfigManager.getOrganizationConfig(realm, null);
    }

    /**
     * {@inheritDoc}
     */
    public String getStringSetting(String realm, String attributeName) throws SSOException, SMSException {
        final Set<String> attribute = getSetting(realm, attributeName);
        if (attribute == null || attribute.isEmpty()) {
            return null;
        }

        return attribute.iterator().next();
    }

    /**
     * {@inheritDoc}
     */
    public Long getLongSetting(String realm, String attributeName) throws SSOException, SMSException {
        return Long.decode(getStringSetting(realm, attributeName));
    }

    /**
     * {@inheritDoc}
     */
    public Boolean getBooleanSetting(String realm, String attributeName) throws SSOException, SMSException {
        return Boolean.valueOf(getStringSetting(realm, attributeName));
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, String> getMapSetting(String realm, String attributeName) throws SSOException, SMSException {
        return MAP_VALUE_PARSER.parse(getSetting(realm, attributeName));
    }

    /**
     * {@inheritDoc}
     */
    //TODO: adapt for getSigningKeyPair
    public KeyPair getSigningKeyPair(String realm, OqsJwsAlgorithm algorithm) throws SMSException, SSOException {
        logger.error("getSigningKeyPair debug1");
        if (OqsJwsAlgorithmType.RSA.equals(algorithm.getAlgorithmType())) {
            logger.error("getSigningKeyPair debugrsa");
            String alias = getStringSetting(realm, OAuth2Constants.OAuth2ProviderService.TOKEN_SIGNING_RSA_KEYSTORE_ALIAS);
            return getServerKeyPair(realm, alias);
        } else if (OqsJwsAlgorithmType.ECDSA.equals(algorithm.getAlgorithmType())) {
            logger.error("getSigningKeyPair debugecdsa");
            Set<String> algorithmAliases = getSetting(realm, OAuth2Constants.OAuth2ProviderService.TOKEN_SIGNING_ECDSA_KEYSTORE_ALIAS);
            for (String algorithmAlias : algorithmAliases) {
                if (StringUtils.isEmpty(algorithmAlias)) {
                    logger.warning("Empty signing key alias");
                    continue;
                }
                String[] aliasSplit = algorithmAlias.split("\\|");
                if (aliasSplit.length != 2) {
                    logger.warning("Invalid signing key alias mapping: " + algorithmAlias);
                    continue;
                }
                if (!aliasSplit[0].equals(algorithm.name())) {
                    logger.warning("Key alias not maching: " + algorithmAlias);
                    continue;
                }
                return getServerKeyPair(realm, aliasSplit[1]);
            }
        } else if (OqsJwsAlgorithmType.PQ.equals(algorithm.getAlgorithmType())) {
            logger.error("getSigningKeyPair PQ");
            logger.error("OpenAMSettingsImpl: algorithm=" + algorithm.getAlgorithm() + " algorithmType=" + algorithm.getAlgorithmType());
            //TODO: extract public key and secret key from keystore
        }
        return new KeyPair(null, null);
    }

    @Override
    public KeyPair getServerKeyPair(String realm, String alias) throws SMSException, SSOException {
        // we late initialize AMKeyProvider as it needs access to the config store to read the
        // system props for storepass, etc.  If we init too early it may not be available
        if (amKeyProvider == null) {
            amKeyProvider = new AMKeyProvider();
        }
        return amKeyProvider.getKeyPair(alias);
    }

    /**
     * {@inheritDoc}
     */
    public String getSSOCookieName() {
        return SystemProperties.get("com.iplanet.am.cookie.name");
    }
}
