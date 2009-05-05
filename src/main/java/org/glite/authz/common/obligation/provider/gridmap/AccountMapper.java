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

package org.glite.authz.common.obligation.provider.gridmap;

import java.util.List;

/**
 * Maps a subject, described by a set of {@link GridMapKey} objects, to an account.
 * 
 * @param <AccountType> an object describing a type of account meaningful to the invoking system
 */
public interface AccountMapper<AccountType> {

    /** Maps a set of grid map keys to a PosixAccount. */
    public AccountType mapToAccount(String subjectid, List<? extends GridMapKey> keys);
}