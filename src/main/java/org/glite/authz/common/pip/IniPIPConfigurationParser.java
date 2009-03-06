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

package org.glite.authz.common.pip;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.ConfigurationException;
import org.ini4j.Ini.Section;

/** A parser that transforms an {@link Section} in to a {@link PolicyInformationPoint}. */
@ThreadSafe
public interface IniPIPConfigurationParser {

    /** "parserClass" configuration property name. */
    public static final String PARSER_CLASS_PROP = "parserClass";

    /** "id" configuration property name. */
    public static final String ID_PROP = "id";

    /**
     * Created a {@link PolicyInformationPoint} from the information within the {@link Section}.
     * 
     * @param iniConfig the INI configuration for the PIP
     * 
     * @return the PIP
     * 
     * @throws ConfigurationException thrown if there is a problem creating the PIP from the given information
     */
    public PolicyInformationPoint parse(Section iniConfig) throws ConfigurationException;
}