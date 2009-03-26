/*
 * Copyright 2009 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.common.pip.provider;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.ini4j.Ini.Section;

/** Configuration parser for {@link X509PolicyInformationPoint} PIPs. */
public class IniX509PIPParser implements IniPIPConfigurationParser {

    /** The name of the {@value} property which gives the absolute path to the 'vomses' directory. */
    public final static String VOMS_INFO_DIR_PROP = "vomsInfoDir";

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configurationBuilder)
            throws ConfigurationException {
        String vomsInfoDir = IniConfigUtil.getString(iniConfig, VOMS_INFO_DIR_PROP, null);
        if (vomsInfoDir == null) {
            return new X509PolicyInformationPoint(iniConfig.getName(), configurationBuilder.getTrustManager());
        } else {
            return new X509PolicyInformationPoint(iniConfig.getName(), configurationBuilder.getTrustManager(),
                    vomsInfoDir);
        }
    }
}