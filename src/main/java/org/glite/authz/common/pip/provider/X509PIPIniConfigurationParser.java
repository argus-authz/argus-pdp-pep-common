
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
            try {
                Files.getReadableFile(vomsInfoDir);
                acTrustMaterial = new PKIStore(vomsInfoDir, PKIStore.TYPE_VOMSDIR);
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