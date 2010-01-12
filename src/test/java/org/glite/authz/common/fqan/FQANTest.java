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

package org.glite.authz.common.fqan;

import java.text.ParseException;

import org.glite.authz.common.fqan.FQAN;

import junit.framework.TestCase;

/**
 *
 */
public class FQANTest extends TestCase {

    public void testFQANParsing() throws ParseException {
        FQAN.parseFQAN("/atlas");
        FQAN.parseFQAN("/atlas/");
        FQAN.parseFQAN("/atlas/Role=NULL");
        FQAN.parseFQAN("/atlas/Role=null");
        FQAN.parseFQAN("/atlas/Role=prod");
        FQAN.parseFQAN("/atlas/Capability=NULL");
        FQAN.parseFQAN("/atlas/Capability=null");
        FQAN.parseFQAN("/atlas/prod");

        try {
            FQAN.parseFQAN("atlas/Role=foo");
            fail("FQAN parser allowed FQAN that did not begin with a '/'");
        } catch (ParseException e) {
            // expected
        }
        
        try {
            FQAN.parseFQAN("/Role=foo");
            fail("FQAN parser allowed FQAN that did not contain a group name");
        } catch (ParseException e) {
            // expected
        }

        try {
            FQAN.parseFQAN("/atlas/Role=foo/Role=bar");
            fail("FQAN parser allowed two roles");
        } catch (ParseException e) {
            // expected
        }

        try {
            FQAN.parseFQAN("/atlas/Capability=foo/Capability=bar");
            fail("FQAN parser allowed two capabilities");
        } catch (ParseException e) {
            // expected
        }
    }

    public void testMatching() throws ParseException {
        FQAN atlas = new FQAN("/atlas", null, null);
        FQAN atlasProd = new FQAN("/atlas/prod", null, null);
        FQAN atlasRoleSGM = new FQAN("/atlas", "sgm", null);
        FQAN atlasProdRoleSGM = new FQAN("/atlas/prod", "sgm", null);
        FQAN atlassi = new FQAN("/atlassi", null, null);

        assertTrue(atlas.equals(new FQAN("/atlas", null, null)));
        assertTrue(atlas.equals(new FQAN("/atlas/", FQAN.NULL, "null")));
        assertFalse(atlas.equals(new FQAN("/atlas/prod", null, null)));
        assertFalse(atlas.equals(new FQAN("/atlas", "sgm", null)));

        assertTrue(atlas.matches("/atlas"));
        assertFalse(atlasProd.matches("/atlas"));
        assertFalse(atlasRoleSGM.matches("/atlas"));
        assertFalse(atlasProdRoleSGM.matches("/atlas"));
        assertFalse(atlassi.matches("/atlas"));

        assertTrue(atlas.matches("/atlas/Role=NULL"));
        assertFalse(atlasProd.matches("/atlas/Role=NULL"));
        assertFalse(atlasRoleSGM.matches("/atlas/Role=NULL"));
        assertFalse(atlasProdRoleSGM.matches("/atlas/Role=NULL"));
        assertFalse(atlassi.matches("/atlas/Role=NULL"));

        assertTrue(atlas.matches("/atlas/Role=*"));
        assertFalse(atlasProd.matches("/atlas/Role=*"));
        assertTrue(atlasRoleSGM.matches("/atlas/Role=*"));
        assertFalse(atlasProdRoleSGM.matches("/atlas/Role=*"));
        assertFalse(atlassi.matches("/atlas/Role=*"));

        assertFalse(atlas.matches("/atlas/prod/Role=*"));
        assertTrue(atlasProd.matches("/atlas/prod/Role=*"));
        assertFalse(atlasRoleSGM.matches("/atlas/prod/Role=*"));
        assertTrue(atlasProdRoleSGM.matches("/atlas/prod/Role=*"));
        assertFalse(atlassi.matches("/atlas/prod/Role=*"));

        try {
            atlas.matches("/atlas*");
            fail("Invalid regular expression was accepted");
        } catch (ParseException e) {
            // expected
        }

        assertTrue(atlas.matches("/atlas/*"));
        assertTrue(atlasProd.matches("/atlas/*"));
        assertFalse(atlasRoleSGM.matches("/atlas/*"));
        assertFalse(atlasProdRoleSGM.matches("/atlas/*"));
        assertFalse(atlassi.matches("/atlas/*"));

        assertFalse(atlas.matches("/atlas/*/Role=sgm"));
        assertFalse(atlasProd.matches("/atlas/*/Role=sgm"));
        assertTrue(atlasRoleSGM.matches("/atlas/*/Role=sgm"));
        assertTrue(atlasProdRoleSGM.matches("/atlas/*/Role=sgm"));
        assertFalse(atlassi.matches("/atlas/*/Role=sgm"));
    }
}