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

package org.glite.authz.common.http;

import javax.servlet.http.HttpServlet;

import org.glite.authz.common.util.Strings;

/** Base class for administration commands which may be registered with a {@link JettyAdminService}. */
public abstract class AbstractAdminCommand extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = 7219580728194810193L;
    
    /** URL path to the command. */
    private String commandPath;

    /**
     * Constructor.
     * 
     * @param command name of the command, should only contain alphabetic characters
     */
    public AbstractAdminCommand(String command) {
        commandPath = Strings.safeTrimOrNullString(command);
        if (commandPath == null) {
            throw new IllegalArgumentException("Command may not be a null or empty string");
        }
        if (!commandPath.startsWith("/")) {
            commandPath = "/" + commandPath;
        }
    }

    /**
     * Gets the URL path that invokes the command.
     * 
     * @return URL path that invokes the command
     */
    public String getCommandPath() {
        return commandPath;
    }
}