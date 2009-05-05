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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.obligation.provider.gridmap.BasicGridMap;
import org.glite.authz.common.obligation.provider.gridmap.X509DNFQANGridMapParser;
import org.glite.authz.common.obligation.provider.gridmap.GridMap;
import org.glite.authz.common.obligation.provider.gridmap.GridMapKey;
import org.glite.authz.common.obligation.provider.gridmap.GridmapParser;
import org.glite.authz.common.util.Files;
import org.opensaml.util.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A builder of {@link PosixAccountMapper} objects. */
@NotThreadSafe
public class PosixAccountMapBuilder {

    /** Time, in minutes, that grid map files are checked for updates. */
    private int refreshPeriod;

    /** Scheduler used to run background tasks. */
    private Timer taskScheduler;

    /** Path to the UID grid map file. */
    private String uidGridMapFilePath;

    /** Parser used to parse the UID grid map file. */
    private GridmapParser uidGridmapParser;

    /** Path the GID grid map file. */
    private String gidGridMapFilePath;

    /** Parser used to parse the GID grid map file. */
    private GridmapParser gidGridmapParser;

    /** Service used to store mappings to a posix account. */
    private StorageService<String, PosixAccount> storageService;

    /**
     * Lifetime, in minutes, of account mappings. Defaults to a value of zero, meaning the account mappings do not
     * expire.
     */
    private int accountMappingLifetime;

    /**
     * Creates a {@link PosixAccountMapper} using the currently configured builder options.
     * 
     * @return the created account mapper
     * 
     * @throws IllegalStateException thrown if all the required properties have not been set
     * @throws IOException thrown if either the UID or GID grid map files can not be read
     */
    public PosixAccountMapper build() throws IllegalStateException, IOException {
        GridmapParser parser = new X509DNFQANGridMapParser();

        GridMap uidGridMap = new BasicGridMap(uidGridmapParser.parse(new FileReader(uidGridMapFilePath)),
                uidGridmapParser.getKeyMatchFunctions());
        GridMap gidGridMap = new BasicGridMap(gidGridmapParser.parse(new FileReader(gidGridMapFilePath)),
                gidGridmapParser.getKeyMatchFunctions());

        PosixAccountMapper mapper;
        if (accountMappingLifetime > 1) {
            mapper = new PosixAccountMapper(uidGridMap, gidGridMap, storageService, accountMappingLifetime * 60 * 1000);
        } else {
            mapper = new PosixAccountMapper(uidGridMap, gidGridMap, storageService);
        }

        RefreshGridMapTask refreshTask = new RefreshGridMapTask(new GridMapProxy(parser, uidGridMap), new GridMapProxy(
                parser, gidGridMap));
        taskScheduler.scheduleAtFixedRate(refreshTask, refreshPeriod, refreshPeriod);

        return mapper;
    }

    /**
     * Gets the period, in minutes, that grid map files are checked for updates.
     * 
     * @return period, in minutes, that grid map files are checked for updates
     */
    public int getRefreshPeriod() {
        return refreshPeriod;
    }

    /**
     * Sets the period, in minutes, that grid map files are checked for updates.
     * 
     * @param period period, in minutes, that grid map files are checked for updates
     */
    public void setRefreshPeriod(int period) {
        refreshPeriod = period;
    }

    /**
     * Gets the scheduler used to run the background grid map refresh task.
     * 
     * @return scheduler used to run the background grid map refresh task
     */
    public Timer getTaskScheduler() {
        return taskScheduler;
    }

    /**
     * Sets the scheduler used to run the background grid map refresh task.
     * 
     * @param scheduler scheduler used to run the background grid map refresh task
     */
    public void setTaskScheduler(Timer scheduler) {
        taskScheduler = scheduler;
    }

    /**
     * Gets the path to the UID grid map file.
     * 
     * @return path to the UID grid map file
     */
    public String getUidGridMapFilePath() {
        return uidGridMapFilePath;
    }

    /**
     * Sets the path to the UID grid map file. This path should be an absolute file path.
     * 
     * @param path path to the UID grid map file
     */
    public void setUidGridMapFilePath(String path) {
        uidGridMapFilePath = path;
    }

    /**
     * Gets the parser used to parse the UID grid map file.
     * 
     * @return parser used to parse the UID grid map file
     */
    public GridmapParser getUidGridMapParse() {
        return uidGridmapParser;
    }

    /**
     * Sets the parser used to parse the UID grid map file.
     * 
     * @param parser parser used to parse the UID grid map file
     */
    public void setUidGridMapParse(GridmapParser parser) {
        uidGridmapParser = parser;
    }

    /**
     * Gets the path to the GID grid map file.
     * 
     * @return path to the GID grid map file
     */
    public String getGidGridMapFilePath() {
        return gidGridMapFilePath;
    }

    /**
     * Sets the path to the GID grid map file. This path should be an absolute file path.
     * 
     * @param path path to the GID grid map file
     */
    public void setGidGridMapFilePath(String path) {
        gidGridMapFilePath = path;
    }

    /**
     * Gets the parser used to parse the GID grid map file.
     * 
     * @return parser used to parse the GID grid map file
     */
    public GridmapParser getGidGridmapParser() {
        return gidGridmapParser;
    }

    /**
     * Sets the parser used to parse the GID grid map file.
     * 
     * @param parser parser used to parse the GID grid map file
     */
    public void setGidGridmapParser(GridmapParser parser) {
        gidGridmapParser = parser;
    }

    /**
     * Gets the service used to store account mappings.
     * 
     * @return service used to store account mappings
     */
    public StorageService<String, PosixAccount> getStorageService() {
        return storageService;
    }

    /**
     * Sets the service used to store account mappings.
     * 
     * @param service service used to store account mappings
     */
    public void setStorageService(StorageService<String, PosixAccount> service) {
        storageService = service;
    }

    /**
     * A proxy that wraps a {@link GridMap}. This is used to allow a refresh task to replace the delegate grid map with
     * an updated version without the knowledge of the component using the grid map.
     */
    private class GridMapProxy implements GridMap {

        /** Parser used to create the delegate grid map. */
        private GridmapParser parser;

        /** The delegate grid map. */
        private GridMap delegate;

        /**
         * Constructor.
         * 
         * @param parser the parser used to create the grid map delegate
         * @param delegate the grid map delegate
         */
        public GridMapProxy(GridmapParser parser, GridMap delegate) {
            this.delegate = delegate;
            this.parser = parser;
        }

        /**
         * Gets the grid map delegate.
         * 
         * @return the grid map delegate
         */
        public GridMap getDelegate() {
            return delegate;
        }

        /**
         * Gets the parser used to create the delegate.
         * 
         * @return parser used to create the delegate
         */
        public GridmapParser getParser() {
            return parser;
        }

        /**
         * Sets the delegate wrapped by this proxy.
         * 
         * @param delegate delegate wrapped by this proxy
         */
        public void setDelegate(GridMap delegate) {
            this.delegate = delegate;
        }

        /** {@inheritDoc} */
        public Map<Class<? extends GridMapKey>, GridMapKeyMatchFunction> getKeyMatchFunctions() {
            return delegate.getKeyMatchFunctions();
        }

        /** {@inheritDoc} */
        public List<Entry> getMapEntries() {
            return delegate.getMapEntries();
        }

        /** {@inheritDoc} */
        public List<String> map(GridMapKey key, boolean matchMultiple) {
            return delegate.map(key, matchMultiple);
        }

    }

    /** A task that refreshes a grid map file if it has been updated since the last time. */
    private class RefreshGridMapTask extends TimerTask {

        /** Class logger. */
        private Logger log = LoggerFactory.getLogger(RefreshGridMapTask.class);

        /** Path to the UID grid map file. */
        private String uidGridMapFilePath;

        /** Time the UID grid map file was last modified. */
        private long uidGridMapFileLastModified = 0;

        /** UID grid map proxy. */
        private GridMapProxy uidGridMap;

        /** Path to the GID grid map file. */
        private String gidGridMapFilePath;

        /** Time the GID grid map file was last modified. */
        private long gidGridMapFileLastModified = 0;

        private GridMapProxy gidGridMap;

        public RefreshGridMapTask(GridMapProxy uidGridMapProxy, GridMapProxy gidGridMapProxy) {
            uidGridMap = uidGridMapProxy;
            gidGridMap = gidGridMapProxy;
        }

        /** {@inheritDoc} */
        public void run() {
            uidGridMapFileLastModified = refreshGridMap(uidGridMap, uidGridMapFilePath, uidGridMapFileLastModified);
            gidGridMapFileLastModified = refreshGridMap(gidGridMap, gidGridMapFilePath, gidGridMapFileLastModified);
        }

        /**
         * Refreshes a {@link GridMap} if the file from which was generated has been updated.
         * 
         * @param proxy proxy containing the grid map to update
         * @param mapFilePath path to the grid map file
         * @param lastUpdated time the grid map was last refreshed
         * 
         * @return the time the grid map was last refreshed
         */
        private long refreshGridMap(GridMapProxy proxy, String mapFilePath, long lastUpdated) {
            try {
                File gridMapFile = Files.getReadableFile(mapFilePath);
                long lastModified = gridMapFile.lastModified();
                if (lastUpdated < lastModified) {
                    GridmapParser gridMapParser = proxy.getParser();
                    GridMap tempGridMap = new BasicGridMap(gridMapParser.parse(new FileReader(gridMapFile)),
                            gridMapParser.getKeyMatchFunctions());
                    proxy.setDelegate(tempGridMap);
                    return lastModified;
                }
            } catch (IOException e) {
                log.error("Unable to refresh grid map file " + mapFilePath + ", encountered the following error:\n", e);
            }

            return lastUpdated;
        }

    }
}