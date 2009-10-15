
package org.glite.authz.common.pip.provider;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
import org.glite.voms.PKIStore;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for {@link X509PIP} PIPs. */
public class X509PIPIniConfigurationParser implements IniPIPConfigurationParser {

    /**
     * The name of the {@value} property the indicates whether PKIX validation will be performed on the certificate
     * chain.
     */
    public final static String PERFORM_PKIX_VALIDATION_PROP = "performPKIXValidation";

    /** The name of the {@value} property which gives the absolute path to the 'vomsdir' directory. */
    public final static String VOMS_INFO_DIR_PROP = "vomsInfoDir";

    /** The name of the {@value} which gives the refresh period, in minutes, for 'vomsdir' information. */
    public static final String VOMS_INFO_REFRESH_PROP = "vomsInfoRefresh";

    /** Default value (1 hour in minutes) of the {@value #VOMS_INFO_REFRESH_PROP} property, {@value} . */
    public static final int DEFAULT_VOMS_INFO_REFRESH = 60;

    /** Default value of {@value #PERFORM_PKIX_VALIDATION_PROP}, {@value} */
    public final static boolean DEFAULT_PERFORM_PKIX_VALIDATION = true;

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(X509PIPIniConfigurationParser.class);

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configurationBuilder)
            throws ConfigurationException {
        PKIStore acTrustMaterial = null;
        
        String vomsInfoDir = IniConfigUtil.getString(iniConfig, VOMS_INFO_DIR_PROP, null);
        if (vomsInfoDir != null) {
            log.info("voms info directory: {}", vomsInfoDir);
            // get refresh interval: default 1h
            int vomsInfoRefresh= IniConfigUtil.getInt(iniConfig, VOMS_INFO_REFRESH_PROP, DEFAULT_VOMS_INFO_REFRESH, 1, Integer.MAX_VALUE);
            vomsInfoRefresh= vomsInfoRefresh * 60 * 1000; // minute -> millis
            log.info("voms info refresh interval: {}ms", vomsInfoRefresh);
            try {
                Files.getFile(vomsInfoDir, false, true, true, false);
                acTrustMaterial = new PKIStore(vomsInfoDir, PKIStore.TYPE_VOMSDIR);
                acTrustMaterial.rescheduleRefresh(vomsInfoRefresh);
            } catch (Exception e) {
                throw new ConfigurationException("Unable to read VOMS AC validation information", e);
            }
        }

        X509PIP pip = new X509PIP(iniConfig.getName(), configurationBuilder.getTrustMaterialStore(), acTrustMaterial);

        boolean performPKIXValidation = IniConfigUtil.getBoolean(iniConfig, PERFORM_PKIX_VALIDATION_PROP,
                DEFAULT_PERFORM_PKIX_VALIDATION);
        log.info("perform PKIX validation on cert chains: {}", performPKIXValidation);
        pip.performPKIXValidation(performPKIXValidation);

        return pip;
    }
}