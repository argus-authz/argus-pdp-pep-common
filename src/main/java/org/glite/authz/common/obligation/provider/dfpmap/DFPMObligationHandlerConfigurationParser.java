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

package org.glite.authz.common.obligation.provider.dfpmap;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.obligation.AbstractObligationHandler;
import org.glite.authz.common.obligation.IniOHConfigurationParser;
import org.glite.authz.common.obligation.provider.dfpmap.impl.DFPMMatchStrategy;
import org.glite.authz.common.obligation.provider.dfpmap.impl.DNPrimaryFQANAccountIndicatorMappingStrategy;
import org.glite.authz.common.obligation.provider.dfpmap.impl.EtcGroupIDMappingStrategy;
import org.glite.authz.common.obligation.provider.dfpmap.impl.EtcPasswdIDMappingStrategy;
import org.glite.authz.common.obligation.provider.dfpmap.impl.FQANGroupNameMappingStrategy;
import org.glite.authz.common.obligation.provider.dfpmap.impl.FQANMatchStrategy;
import org.glite.authz.common.obligation.provider.dfpmap.impl.GridMapDirPoolAccountManager;
import org.glite.authz.common.obligation.provider.dfpmap.impl.OrderedDFPM;
import org.glite.authz.common.obligation.provider.dfpmap.impl.X509MatchStrategy;
import org.glite.authz.common.util.Files;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** INI configuration parser that constructs {@link DFPMObligationHandler}s. */
public class DFPMObligationHandlerConfigurationParser implements IniOHConfigurationParser {

    /**
     * The name of the {@value} property which gives the absolute path to the mapping file that maps subjects to account
     * indicator.
     */
    public static final String ACCOUNT_MAP_FILE_PROP = "accountMapFile";

    /**
     * The name of the {@value} property that indicates the account indicator associated with the subject's DN should be
     * preferred over the one from the primary FQAN.
     */
    public static final String PREFER_DN_FOR_LOGIN_NAME_PROP = "preferDNForLoginName";

    /**
     * The name of the {@value} property which gives the absolute path to the mapping file that maps subjects to groups.
     */
    public static final String GROUP_MAP_FILE_PROP = "groupMapFile";

    /** The name of the {@value} property which gives the interval, in minutes, mapping files are checked for changes. */
    public static final String MAP_REFRESH_PERIOD_PROP = "refreshPeriod";

    /**
     * The name of the {@value} property which gives the the absolute path to the directory that grid mappings are
     * stored.
     */
    public static final String GRID_MAP_DIR_PROP = "gridMapDir";

    /** The name of the {@value} property which gives the lifetime, in minutes, of a mapping in to a POSIX account. */
    public static final String ACCOUNT_MAP_LIFETIME = "mappingLifetime";

    /** The default value of the {@value #PREFER_DN_FOR_LOGIN_NAME_PROP} property: {@value} . */
    public static final boolean PREFER_DN_FOR_LOGIN_NAME_DEFAULT = false;

    /** The default value of the {@value IniOHConfigurationParser#PRECEDENCE_PROP} property: {@value} . */
    public static final int DEFAULT_PRECENDENCE = 0;

    /** The default value of the {@value #MAP_REFRESH_PERIOD_PROP} property: {@value} . */
    public static final int DEFAULT_MAP_REFRESH_PERIOD = 15;

    /** The default value of the {@value #ACCOUNT_MAP_LIFETIME} property: {@value} . */
    public static final int DEFAULT_ACCOUNT_MAP_LIFETIME = 43200;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DFPMObligationHandlerConfigurationParser.class);

    /** {@inheritDoc} */
    public AbstractObligationHandler parse(Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {

        int precendence = IniConfigUtil.getInt(iniConfig, PRECEDENCE_PROP, DEFAULT_PRECENDENCE, 0, Integer.MAX_VALUE);
        log.debug("handler precendence: {}", precendence);

        String accountMapFile = IniConfigUtil.getString(iniConfig, ACCOUNT_MAP_FILE_PROP);
        log.debug("login name mapping file: {}", accountMapFile);

        boolean preferDNForLoginName = IniConfigUtil.getBoolean(iniConfig, PREFER_DN_FOR_LOGIN_NAME_PROP,
                PREFER_DN_FOR_LOGIN_NAME_DEFAULT);
        log.debug("prefer DN login name mappings: {}", preferDNForLoginName);

        String groupMapFile = IniConfigUtil.getString(iniConfig, GROUP_MAP_FILE_PROP);
        log.debug("group name mapping file: {}", groupMapFile);

        int mapRefreshPeriod = IniConfigUtil.getInt(iniConfig, MAP_REFRESH_PERIOD_PROP, DEFAULT_MAP_REFRESH_PERIOD, 1,
                Integer.MAX_VALUE);
        log.debug("mapping file refresh period: {} mins", mapRefreshPeriod);

        String gridMapDir = IniConfigUtil.getString(iniConfig, GRID_MAP_DIR_PROP);
        log.debug("grid mapping directory: {}", gridMapDir);

        AccountMapper accountMapper = buildAccountMapper(accountMapFile, preferDNForLoginName, gridMapDir,
                mapRefreshPeriod, gridMapDir);
        return new DFPMObligationHandler(iniConfig.getName(), accountMapper);
    }

    /**
     * Builds an account mapper for the obligaton handler.
     * 
     * @param accountMapFile file containing mappings to account indicators
     * @param preferDNMappingForAccountIndicator whether account indicators derived from DN mappings should be preferred
     *            over those derived from FQAN mappings
     * @param groupMapFile file containing mappings to groups
     * @param mapRefreshPeriod mapping file re-read and refresh period
     * @param gridMapDir directory used as backing store for mappings
     * 
     * @return the constructed account mapper
     * 
     * @throws ConfigurationException thrown if the mapping files can not be read or parsed or if the grid map directory
     *             is not read and writable
     */
    private AccountMapper buildAccountMapper(String accountMapFile, boolean preferDNMappingForAccountIndicator,
            String groupMapFile, int mapRefreshPeriod, String gridMapDir) throws ConfigurationException {
        DFPMMatchStrategy<X500Principal> dnMatchStrategy = new X509MatchStrategy();
        DFPMMatchStrategy<FQAN> fqanMatchStrategy = new FQANMatchStrategy();

        DFPM accountIndicatorMap = buildMapping(accountMapFile, mapRefreshPeriod);
        DFPM groupMap = buildMapping(groupMapFile, mapRefreshPeriod);
        PoolAccountManager pam = buildPoolAccountManager(gridMapDir);

        DNPrimaryFQANAccountIndicatorMappingStrategy aimStrategy = new DNPrimaryFQANAccountIndicatorMappingStrategy(
                accountIndicatorMap, dnMatchStrategy, fqanMatchStrategy, preferDNMappingForAccountIndicator);
        FQANGroupNameMappingStrategy gnmStrategy = new FQANGroupNameMappingStrategy(groupMap, fqanMatchStrategy);
        EtcPasswdIDMappingStrategy uidMappingStrategy = new EtcPasswdIDMappingStrategy();
        EtcGroupIDMappingStrategy gidMappingStrategy = new EtcGroupIDMappingStrategy();

        return new AccountMapper(aimStrategy, gnmStrategy, pam, uidMappingStrategy, gidMappingStrategy);
    }

    /**
     * Builds an mapping set that refreshes with the given period.
     * 
     * @param mappingFile file containing the mapping information
     * @param refreshPeriod period between refresh of the mapping from the mapping file
     * 
     * @return the built mapping
     * 
     * @throws ConfigurationException thrown if the is a problem reading the mapping file
     */
    private DFPM buildMapping(String mappingFile, int refreshPeriod) throws ConfigurationException {
        try {
            Files.getReadableFile(mappingFile);
        } catch (IOException e) {
            log.error("Unable to read map file " + mappingFile, e);
            throw new ConfigurationException("Unable to read map file " + mappingFile, e);
        }

        DFPMFileParser fileParser = new DFPMFileParser();
        OrderedDFPM map = new OrderedDFPM();
        fileParser.parse(map, new InputStreamReader(this.getClass().getResourceAsStream(mappingFile)));
        return map;
    }

    /**
     * Builds a pool account manager.
     * 
     * @param gridMapDirPath path used to persist pool account mappings on the filesystem
     * 
     * @return the pool account manager
     * 
     * @throws ConfigurationException thrown fi the given grid map directory is not a directory, can not be read, or can
     *             not be written to
     */
    private PoolAccountManager buildPoolAccountManager(String gridMapDirPath) throws ConfigurationException {
        File gridMapDir = new File(gridMapDirPath);
        if (!gridMapDir.exists()) {
            throw new ConfigurationException("Grid map directory " + gridMapDir.getAbsolutePath() + " does not exist");
        }

        if (!gridMapDir.canRead()) {
            throw new ConfigurationException("Grid map directory " + gridMapDir.getAbsolutePath()
                    + " is not readable by this process");
        }

        if (!gridMapDir.canWrite()) {
            throw new ConfigurationException("Grid map directory " + gridMapDir.getAbsolutePath()
                    + " is not writable by this process");
        }
        return new GridMapDirPoolAccountManager(gridMapDir);
    }
}