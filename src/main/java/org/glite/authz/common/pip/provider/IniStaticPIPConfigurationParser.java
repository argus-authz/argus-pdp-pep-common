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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;

/** Configuration parser for {@link StaticPIP}. */
@ThreadSafe
public class IniStaticPIPConfigurationParser implements IniPIPConfigurationParser {

    /** Configuration property name of for the static attributes files. */
    public static final String CONFIG_FILE_PROP = "staticAttributesFile";

    /** Configuration property name of for the attribute issuer ID. */
    public static final String ATTRIBUTE_ISSUER_PROP = "attributeIssuer";

    /**
     * Configuration property name of for whether resource attributes should be added to all resources within a request.
     */
    public static final String RESOURCE_ATTRIBUTES_IN_ALL_PROP = "includeResourceAttribtuesInAllResources";

    /**
     * Configuration property name of for whether subject attributes should be added to all subject within a request.
     */
    public static final String SUBJECT_ATTRIBUTES_IN_ALL_PROP = "includeSubjectAttribtuesInAllSubjects";

    /** Section header name that identifies action attributes. */
    public static final String ACTION_SECTION_HEADER = "ACTION";

    /** Section header name that identifies environment attributes. */
    public static final String ENVIRONMENT_SECTION_HEADER = "ENVIRONMENT";

    /** Section header name that identifies resource attributes. */
    public static final String RESOURCE_SECTION_HEADER = "RESOURCE";

    /** Section header name that identifies subject attributes. */
    public static final String SUBJECT_SECTION_HEADER = "SUBJECT";

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig) throws ConfigurationException {
        String staticAttributesFilePath = iniConfig.get(CONFIG_FILE_PROP);
        Ini iniFile = readIniFile(staticAttributesFilePath);

        String pipId = Strings.safeTrimOrNullString(iniConfig.getName());
        Map<String, List<String>> actionAttributes = iniSectionToAttributeMap(iniFile.get(ACTION_SECTION_HEADER));
        Map<String, List<String>> environmentAttributes = iniSectionToAttributeMap(iniFile
                .get(ENVIRONMENT_SECTION_HEADER));
        Map<String, List<String>> resourceAttributes = iniSectionToAttributeMap(iniFile.get(RESOURCE_SECTION_HEADER));
        Map<String, List<String>> subjectAttributes = iniSectionToAttributeMap(iniFile.get(SUBJECT_SECTION_HEADER));

        StaticPIP pip = new StaticPIP(pipId, actionAttributes, environmentAttributes, resourceAttributes,
                subjectAttributes);

        if (iniConfig.containsKey(ATTRIBUTE_ISSUER_PROP)) {
            pip.setAttributeIssuer(Strings.safeTrimOrNullString(iniConfig.get(ATTRIBUTE_ISSUER_PROP)));
        }

        if (iniConfig.containsKey(RESOURCE_ATTRIBUTES_IN_ALL_PROP)) {
            pip.setAddAttributesToAllResources(Boolean.parseBoolean(iniConfig.get(RESOURCE_ATTRIBUTES_IN_ALL_PROP)));
        }

        if (iniConfig.containsKey(SUBJECT_ATTRIBUTES_IN_ALL_PROP)) {
            pip.setAddAttributesToAllSubjects(Boolean.parseBoolean(iniConfig.get(SUBJECT_ATTRIBUTES_IN_ALL_PROP)));
        }

        return pip;
    }

    /**
     * Reads in the static attributes configuration file.
     * 
     * @param filePath the path to the configuration file
     * 
     * @return the parsed INI file
     * 
     * @throws ConfigurationException thrown if the INI file is invalid
     */
    private Ini readIniFile(String filePath) throws ConfigurationException {
        File staticAttributesFile = null;

        try {
            staticAttributesFile = Files.getReadableFile(filePath);
        } catch (IOException e) {
            throw new ConfigurationException(e.getMessage());
        }

        Ini iniFile = new Ini();
        try {
            iniFile.load(new FileReader(staticAttributesFile));
        } catch (Exception e) {
            throw new ConfigurationException("Unable to parse static attribtues file " + filePath, e);
        }

        return iniFile;
    }

    /**
     * Converts an INI section into a map of attributes. The map key is the ID of the attribute, the map value is the
     * list of attribute values.
     * 
     * @param section the section to convert
     * 
     * @return the attribute map
     */
    private Map<String, List<String>> iniSectionToAttributeMap(Section section) {
        if (section == null) {
            return null;
        }
        Map<String, List<String>> attributeMap = new HashMap<String, List<String>>();

        String attributeValue;
        List<String> attributeValues;
        for (String attributeName : section.keySet()) {
            attributeValues = new ArrayList<String>();
            StringTokenizer tokens = new StringTokenizer(section.get(attributeName), "|");
            while (tokens.hasMoreElements()) {
                attributeValue = Strings.safeTrimOrNullString(tokens.nextToken());
                if (attributeValue != null) {
                    attributeValues.add(attributeValue);
                }
            }
            attributeMap.put(attributeName, attributeValues);
        }

        return attributeMap;
    }

}