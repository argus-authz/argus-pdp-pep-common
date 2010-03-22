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

/**
 * This package contains base classes used to configure the various PDP and PEP components.  The configurations 
 * are meant to be immutable objects created by configuration builders.  This helps ensure thread-safety.  The 
 * current mechanism for creating the configuration objects is through the use of INI files however new methods
 * could be used by implementing new {@link org.glite.authz.common.config.ConfigurationParser} objects.
 */
package org.glite.authz.common.config;