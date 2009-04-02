package org.glite.authz.common.pip.provider;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini.Section;

/** Configuration parser for an {@link EnvironmentTimePIP} */
public class EnvironmentTimePIPIniConfigurationParser implements IniPIPConfigurationParser {

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        return new EnvironmentTimePIP(Strings.safeTrimOrNullString(iniConfig.getName()));
    }
}