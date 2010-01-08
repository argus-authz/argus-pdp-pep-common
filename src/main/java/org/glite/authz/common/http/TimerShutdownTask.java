/*
 * Copyright 2010 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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

package org.glite.authz.common.http;

import java.util.Timer;

/**
 * A task that shuts down a {@link Timer}. This task is intended to be used as a shutdown task within a
 * {@link JettyAdminService}.
 */
public class TimerShutdownTask implements Runnable {

    /** Timer to be shutdown. */
    private Timer backgroundTimer;

    /**
     * Constructor.
     * 
     * @param timer timer to be shutdown.
     */
    public TimerShutdownTask(Timer timer) {
        if (timer == null) {
            throw new IllegalArgumentException("Timer may not be null");
        }
        backgroundTimer = timer;
    }

    /** {@inheritDoc} */
    public void run() {
        backgroundTimer.cancel();
    }
}