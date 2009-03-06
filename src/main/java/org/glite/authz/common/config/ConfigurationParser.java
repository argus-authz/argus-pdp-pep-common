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

package org.glite.authz.common.config;

import java.io.Reader;

/**
 * A parser for configurations.
 * 
 * @param <ConfigurationType> the type of configuration produced by this parser
 */
public interface ConfigurationParser<ConfigurationType extends AbstractConfiguration> {

    /**
     * Reads a given configuration and creates the appropriate {@link AbstractConfiguration}.
     * 
     * @param config the configuration to be read
     * 
     * @return the {@link AbstractConfiguration} containing the information from the provided config
     * 
     * @throws ConfigurationException thrown if there is a problem creating the configuration from the given information
     */
    public ConfigurationType parse(String config) throws ConfigurationException;

    /**
     * Reads a given configuration and creates the appropriate {@link AbstractConfiguration}.
     * 
     * @param config the configuration to be read
     * 
     * @return the {@link AbstractConfiguration} containing the information from the provided config
     * 
     * @throws ConfigurationException thrown if there is a problem creating the configuration from the given information
     */
    public ConfigurationType parse(Reader config) throws ConfigurationException;
}