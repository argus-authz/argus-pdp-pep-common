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

package org.glite.authz.common.logging;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.TimerTask;

import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.status.ErrorStatus;
import ch.qos.logback.core.status.StatusManager;

/** A work task for reloading the logging configuration. */
public class LoggingReloadTask extends TimerTask {
    
    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(LoggingReloadTask.class);

    /** Path to the logging configuration file. */
    private String loggingConfigFilePath;

    /** The last time the logging configuration was modified. */
    private long lastModification;

    /**
     * Constructor.
     * 
     * @param configFilePath path to the logging configuration file to watch for changes and reload.
     */
    public LoggingReloadTask(String configFilePath) {
        loggingConfigFilePath = Strings.safeTrimOrNullString(configFilePath);
        lastModification = -1;
    }

    /** {@inheritDoc} */
    public void run() {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        StatusManager statusManager = loggerContext.getStatusManager();

        File loggingConfigFile = null;
        try {
            loggingConfigFile = Files.getReadableFile(loggingConfigFilePath);
        } catch (IOException e) {
            log.error("Error loading logging configuration file: " + loggingConfigFilePath, e);
            return;
        }

        if (lastModification >= loggingConfigFile.lastModified()) {
            // file hasn't changed since the last time we looked
            log.trace("Logging configuration has not changed, skipping reload");
            return;
        }

        try {
            loggerContext.reset();
            JoranConfigurator configurator = new JoranConfigurator();
            configurator.setContext(loggerContext);
            FileInputStream fin = new FileInputStream(loggingConfigFile);
            configurator.doConfigure(fin);
            fin.close();
            loggerContext.start();
            log.info("Loaded new logging configuration file {}", loggingConfigFile.getAbsoluteFile());
            lastModification = loggingConfigFile.lastModified();
        } catch (JoranException e) {
            statusManager.add(new ErrorStatus("Error loading logging configuration file: "
                    + loggingConfigFile.getAbsolutePath(), this, e));
        } catch (IOException e) {
            statusManager.add(new ErrorStatus("Error loading logging configuration file: "
                    + loggingConfigFile.getAbsolutePath(), this, e));
        }
    }
}