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
package org.glite.authz.common.logging;

/** Constants related to logging. */
public class LoggingConstants {

    /** Name of a category where various messages are logged. */
    public final static String MESSAGE_CATEGORY = "org.glite.authz.message";
    
    /** Name of the category to which protocol messages are written. */
    public final static String PROTOCOL_MESSAGE_CATEGORY = MESSAGE_CATEGORY + ".protocol";
    
    /** Name of the category to which policies are written. */
    public final static String POLICY_MESSAGE_CATEGORY = MESSAGE_CATEGORY+ ".policy";
    
    /** Name of the category to which access messages are written. */
    public final static String ACCESS_CATEGORY = "org.glite.authz.access";
    
    /** Name of the category to which audit messages are written. */
    public final static String AUDIT_CATEGORY = "org.glite.authz.audit";
}