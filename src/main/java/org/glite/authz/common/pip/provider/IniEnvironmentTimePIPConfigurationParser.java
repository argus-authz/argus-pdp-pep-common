/*
 * Copyright 2008 EGEE Collaboration
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

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini.Section;

/** Configuration parser for {@link EnvironmentTimePIP}. */
@ThreadSafe
public class IniEnvironmentTimePIPConfigurationParser implements IniPIPConfigurationParser {

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig) throws ConfigurationException {
        return new EnvironmentTimePIP(Strings.safeTrimOrNullString(iniConfig.get(ID_PROP)));
    }
}