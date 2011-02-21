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

import java.util.ArrayList;
import java.util.List;

import org.glite.authz.common.util.Strings;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Utilities for getting values for configuration files. */
public class IniConfigUtil {

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(IniConfigUtil.class);

    /**
     * Extracts a boolean value from a configuration property. The values 'true', 'yes', and '1' are treated as true,
     * the values 'false', 'no', '0' are treated as false, use case insensitive matching. If the value is anything else,
     * or not present, the default value is used.
     * 
     * @param configSection configuration section from which to extract the attribute
     * @param propName name of the configuration property
     * @param defaultValue default value for the property
     * 
     * @return the value
     */
    public static boolean getBoolean(Section configSection, String propName, boolean defaultValue) {
        String value = getString(configSection, propName, null);

        if ("true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value) || "1".equalsIgnoreCase(value)) {
            return true;
        }

        if ("false".equalsIgnoreCase(value) || "no".equalsIgnoreCase(value) || "0".equalsIgnoreCase(value)) {
            return false;
        }

        return defaultValue;
    }

    /**
     * Extracts a boolean value from a configuration property. The values 'true', 'yes', and '1' are treated as true,
     * the values 'false', 'no', '0' are treated as false, use case insensitive matching. If the value is anything else,
     * or not present, the default value is used.
     * 
     * @param configSection configuration section from which to extract the attribute
     * @param propName name of the configuration property
     * 
     * @return the value
     * 
     * @throws ConfigurationException thrown if given configuration section does not contain a property with the given
     *             name
     */
    public static boolean getBoolean(Section configSection, String propName) throws ConfigurationException {
        String value = getString(configSection, propName, null);

        if ("true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value) || "1".equalsIgnoreCase(value)) {
            return true;
        }

        if ("false".equalsIgnoreCase(value) || "no".equalsIgnoreCase(value) || "0".equalsIgnoreCase(value)) {
            return false;
        }

        throw new ConfigurationException("INI configuration section " + configSection.getName()
                + " does not contain the required property " + propName);
    }

    /**
     * Extracts a string value from a configuration property. If the property does not exist or has a null or empty
     * value the default value is used.
     * 
     * @param configSection configuration section from which to extract the attribute
     * @param propName name of the configuration property
     * @param defaultValue default value for the property
     * 
     * @return the value of the property
     */
    public static String getString(Section configSection, String propName, String defaultValue) {
        String propValue = Strings.safeTrimOrNullString(configSection.get(propName));

        if (propValue == null) {
            propValue = defaultValue;
        }

        return propValue;
    }

    /**
     * Extracts a string value from a configuration property.
     * 
     * @param configSection configuration section from which to extract the attribute
     * @param propName name of the configuration property
     * 
     * @return the value of the property
     * 
     * @throws ConfigurationException thrown if the value does not exist or has a null/empty value
     */
    public static String getString(Section configSection, String propName) throws ConfigurationException {
        String propValue = Strings.safeTrimOrNullString(configSection.get(propName));

        if (propValue != null) {
            return propValue;
        }

        throw new ConfigurationException("INI configuration section " + configSection.getName()
                + " does not contain the required property " + propName);
    }

    /**
     * Extracts an integer value from a configuration property.
     * 
     * @param configSection configuration section from which to extract the attribute
     * @param propName name of the configuration property
     * @param minValue minimum value of the property
     * @param maxValue maximum value of the property
     * 
     * @return the value for the property
     * 
     * @throws ConfigurationException thrown if there is a problem getting the required integer value
     */
    public static int getInt(Section configSection, String propName, int minValue, int maxValue)
            throws ConfigurationException {
        if (configSection.containsKey(propName)) {
            try {
                int tempInt = Integer.parseInt(configSection.get(propName));
                if (tempInt < minValue) {
                    throw new ConfigurationException(propName + " must be greater than " + minValue);
                }
                if (tempInt > maxValue) {
                    throw new ConfigurationException(propName + " must be less than " + maxValue);
                }
                return tempInt;
            } catch (NumberFormatException e) {
                throw new ConfigurationException(propName + " is not a valid integer");
            }
        }

        throw new ConfigurationException("INI configuration section " + configSection.getName()
                + " does not contain the required property " + propName);
    }

    /**
     * Extracts an integer value from a configuration property. If the property does not exist or has an invalid value
     * the default value is returned.
     * 
     * @param configSection configuration section from which to extract the attribute
     * @param propName name of the configuration property
     * @param defaultValue default value of the property
     * @param minValue minimum value of the property
     * @param maxValue maximum value of the property
     * 
     * @return the value for the property
     */
    public static int getInt(Section configSection, String propName, int defaultValue, int minValue, int maxValue) {
        String strValue = Strings.safeTrimOrNullString(configSection.get(propName));
        if (strValue != null) {
            try {
                int tempInt = Integer.parseInt(strValue);
                if (tempInt >= minValue && tempInt <= maxValue) {
                    return tempInt;
                } else {
                    log.warn(
                            "Property {} in configuration section {} with a value of {} was not greater than or equal to {} and less than or equal to {}, using default value of {}",
                            new Object[] { propName, configSection.getName(), tempInt, minValue, maxValue, defaultValue });
                }
            } catch (NumberFormatException e) {
                log.warn(
                        "Property {} in configuration section {} was not a valid integer, using default value of {}, using default value of {}",
                        new Object[] { propName, configSection.getName(), strValue, defaultValue });
            }
        }

        return defaultValue;
    }

    /** Separator for the strings list elements */
    public static final String STRING_LIST_SEPARATOR = " ";

    /**
     * Extracts a string list values from a configuration property, the values are separated with
     * {@value #STRING_LIST_SEPARATOR} (space).
     * 
     * @param configSection configuration section from which to extract the strings list
     * @param propName name of the configuration property
     * 
     * @return the string values array of the property
     * 
     * @throws ConfigurationException thrown if the configuration property does not exist.
     */
    public static String[] getStringsArray(Section configSection, String propName) throws ConfigurationException {
        return getStringsArray(configSection, propName, STRING_LIST_SEPARATOR);
    }

    /**
     * Extracts a string list values from a configuration property, the values are separated with
     * {@value #STRING_LIST_SEPARATOR} (space).
     * 
     * @param configSection configuration section from which to extract the strings list
     * @param propName name of the configuration property
     * @param defaultValues the default list values to return if the configuration property does not exist.
     * @return the string values array of the property
     */
    public static String[] getStringsArray(Section configSection, String propName, String[] defaultValues) {
        String[] values = null;
        try {
            values = getStringsArray(configSection, propName, STRING_LIST_SEPARATOR);
        } catch (ConfigurationException e) {
            return defaultValues;
        }
        return values;
    }

    private static String[] getStringsArray(Section configSection, String propName, String listSeparator)
            throws ConfigurationException {
        String propValues = configSection.get(propName);
        if (propValues == null) {
            throw new ConfigurationException("INI configuration section " + configSection.getName()
                    + " does not contain the required property " + propName);

        }
        List<String> values = new ArrayList<String>();
        for (String value : propValues.split(listSeparator)) {
            String trimmedValue = Strings.safeTrimOrNullString(value);
            if (trimmedValue != null) {
                values.add(trimmedValue);
            }
        }
        return values.toArray(new String[values.size()]);
    }
}