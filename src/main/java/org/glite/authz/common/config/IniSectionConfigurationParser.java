/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.common.config;

import org.ini4j.Ini;

/** A generic parser that parses an INI {@link Section} and creates an ObjectType. */
public interface IniSectionConfigurationParser<ObjectType> {

    /**
     * The name of the {@value} property which gives the fully qualified class
     * name of the ObjectType configuration parser.
     */
    public static final String PARSER_CLASS_PROP= "parserClass";

    /**
     * Creates a ObjectType from the information within
     * the {@link Section}.
     * 
     * @param iniConfig
     *            the INI configuration for the obligation handler
     * @param configBuilder
     *            the configuration builder currently being populated
     * 
     * @return the obligation handler
     * 
     * @throws ConfigurationException
     *             thrown if there is a problem creating the obligation handler
     *             from the given information
     */
    public ObjectType parse(Ini.Section iniConfig,
            AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException;
}
