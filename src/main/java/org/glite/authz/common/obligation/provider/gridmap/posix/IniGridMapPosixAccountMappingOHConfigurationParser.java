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

package org.glite.authz.common.obligation.provider.gridmap.posix;

import java.io.IOException;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.obligation.AbstractObligationHandler;
import org.glite.authz.common.obligation.IniOHConfigurationParser;
import org.glite.authz.common.obligation.provider.gridmap.X509DNFQANGridMapParser;
import org.glite.authz.common.util.Files;
import org.ini4j.Ini.Section;
import org.opensaml.util.storage.MapBasedStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** An INI configuration file parser that creates {@link GridMapPosixAccountMappingObligationHandler} instances. */
public class IniGridMapPosixAccountMappingOHConfigurationParser implements IniOHConfigurationParser {

    /**
     * The name of the {@value} property which gives the absolute path to the mapping file that maps subjects to
     * accounts.
     */
    public static final String UID_MAP_FILE_PROP = "accountMapFile";

    /**
     * The name of the {@value} property which gives the absolute path to the mapping file that maps subjects to groups.
     */
    public static final String GID_MAP_FILE_PROP = "groupMapFile";

    /** The name of the {@value} property which gives the interval, in minutes, mapping files are checked for changes. */
    public static final String MAP_REFRESH_INTERVAL_PROP = "refreshInterval";

    /** The name of the {@value} property which gives the lifetime, in minutes, of a mapping in to a POSIX account. */
    public static final String ACCOUNT_MAP_LIFETIME = "mappingLifetime";

    /** The default value of the {@value IniOHConfigurationParser#PRECEDENCE_PROP} property: {@value} . */
    public static final int DEFAULT_PRECENDENCE = 0;

    /** The default value of the {@value #MAP_REFRESH_INTERVAL_PROP} property: {@value} . */
    public static final int DEFAULT_MAP_REFRESH_INTERVAL = 15;

    /** The default value of the {@value #ACCOUNT_MAP_LIFETIME} property: {@value} . */
    public static final int DEFAULT_ACCOUNT_MAP_LIFETIME = 43200;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(IniGridMapPosixAccountMappingOHConfigurationParser.class);

    /** {@inheritDoc} */
    public AbstractObligationHandler parse(Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {

        int precendence = IniConfigUtil.getInt(iniConfig, PRECEDENCE_PROP, DEFAULT_PRECENDENCE, 0, Integer.MAX_VALUE);
        log.debug("handler precendence: {}", precendence);

        String uidMapFile = IniConfigUtil.getString(iniConfig, UID_MAP_FILE_PROP);
        log.debug("UID mapping file: {}", uidMapFile);

        String gidMapFile = IniConfigUtil.getString(iniConfig, GID_MAP_FILE_PROP);
        log.debug("GID mapping file: {}", gidMapFile);

        int mapRefreshPeriod = IniConfigUtil.getInt(iniConfig, MAP_REFRESH_INTERVAL_PROP, DEFAULT_MAP_REFRESH_INTERVAL,
                1, Integer.MAX_VALUE);
        log.debug("mapping file refresh period: {} mins", mapRefreshPeriod);

        int accountMapLifetime = IniConfigUtil.getInt(iniConfig, ACCOUNT_MAP_LIFETIME, DEFAULT_ACCOUNT_MAP_LIFETIME, 1,
                Integer.MAX_VALUE);
        log.debug("account mapping lifetime: {} mins", accountMapLifetime);

        try {
            Files.getReadableFile(uidMapFile);
        } catch (IOException e) {
            log.error("Unable to read UID map file " + uidMapFile, e);
            throw new ConfigurationException("Unable to read UID map file " + uidMapFile, e);
        }

        try {
            Files.getReadableFile(gidMapFile);
        } catch (IOException e) {
            log.error("Unable to read UID map file " + gidMapFile, e);
            throw new ConfigurationException("Unable to read GID map file " + gidMapFile, e);
        }

        X509DNFQANGridMapParser gridMapParser = new X509DNFQANGridMapParser();
        MapBasedStorageService<String, PosixAccount> mappingStore = new MapBasedStorageService<String, PosixAccount>();

        PosixAccountMapBuilder accountMapperBuilder = new PosixAccountMapBuilder();
        accountMapperBuilder.setAccountMappingLifetime(accountMapLifetime);
        accountMapperBuilder.setGidGridMapFilePath(gidMapFile);
        accountMapperBuilder.setGidGridmapParser(gridMapParser);
        accountMapperBuilder.setRefreshPeriod(mapRefreshPeriod);
        accountMapperBuilder.setStorageService(mappingStore);
        accountMapperBuilder.setTaskScheduler(null);
        accountMapperBuilder.setUidGridMapFilePath(uidMapFile);
        accountMapperBuilder.setUidGridMapParser(gridMapParser);

        try {
            return new GridMapPosixAccountMappingObligationHandler(
                    GridMapPosixAccountMappingObligationHandler.MAPPING_OB_ID, precendence, accountMapperBuilder
                            .build());
        } catch (IOException e) {
            log.error("Unable to process map files", e);
            throw new ConfigurationException("Unable to process map files", e);
        }
    }
}