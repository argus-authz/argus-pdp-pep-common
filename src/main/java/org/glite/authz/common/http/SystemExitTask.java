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

import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A command that execute a System.exit(0) after a given delay. */
public class SystemExitTask implements Runnable {

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(SystemExitTask.class);

    /** Delay before system exit in milliseconds. Default: 1 sec */
    private long delay_= 1000;

    /** Timer for delay */
    Timer delayTimer_= new Timer(true);

    /**
     * Constructor.
     * 
     * @param delay
     *            in millisecond before executing a System.exit(0)
     */
    public SystemExitTask(long delay) {
        delay_= delay;
    }

    /** {@inheritDoc} */
    public void run() {
        delayTimer_.schedule(new TimerTask() {
            public void run() {
                log.info("Service exit.");
                System.exit(0);
            }
        }, delay_);
    }
}