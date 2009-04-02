package org.glite.authz.common.pip.provider;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.ini4j.Ini.Section;

/** Configuration parser for {@link X509PIP} PIPs. */
public class X509PIPIniConfigurationParser implements IniPIPConfigurationParser {

    /** The name of the {@value} property which gives the absolute path to the 'vomsdir' directory. */
    public final static String VOMS_INFO_DIR_PROP = "vomsInfoDir";

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configurationBuilder)
            throws ConfigurationException {
        String vomsInfoDir = IniConfigUtil.getString(iniConfig, VOMS_INFO_DIR_PROP, null);
        if (vomsInfoDir == null) {
            return new X509PIP(iniConfig.getName(), configurationBuilder.getTrustManager());
        } else {
            return new X509PIP(iniConfig.getName(), configurationBuilder.getTrustManager(),
                    vomsInfoDir);
        }
    }
}