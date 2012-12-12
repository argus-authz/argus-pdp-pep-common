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

package org.glite.authz.common.fqan;

import java.text.ParseException;

import org.glite.authz.common.fqan.FQAN;

import junit.framework.TestCase;

/**
 *
 */
public class FQANTest extends TestCase {

    public void testParseFQAN() throws ParseException {
        FQAN.parseFQAN("/atlas");
        FQAN.parseFQAN("/atlas/");
        FQAN.parseFQAN("/atlas/Role=NULL");
        FQAN.parseFQAN("/atlas/Role=null");
        FQAN.parseFQAN("/atlas/Role=prod");
        FQAN.parseFQAN("/atlas/Capability=NULL");
        FQAN.parseFQAN("/atlas/Capability=null");
        FQAN.parseFQAN("/atlas/prod");
        FQAN.parseFQAN("/atlas/prod/Role=prod/Capability=NULL");
        FQAN.parseFQAN("/atlas/prod/Role=null/Capability=NULL");

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

    public void testGroupAndRole()  throws ParseException {
        FQAN fqan= FQAN.parseFQAN("/atlas/analysis/Role=pilot");
        System.out.println("FQAN: " + fqan);
        System.out.println("group: " + fqan.getGroupName());
        assertEquals("/atlas/analysis", fqan.getGroupName());
        System.out.println("role: " + fqan.getRole());
        assertEquals("pilot", fqan.getRole());
        
    }
    public void testInvalidRegexp() throws ParseException {
        FQAN atlas = new FQAN("/atlas");

        try {
            atlas.matches("/*");
            fail("Invalid FQAN group regexp was accepted: VO not specified");
        } catch (ParseException e) {
            // expected
        }

        try {
            atlas.matches("/atlas*");
            fail("Invalid FQAN group regexp was accepted");
        } catch (ParseException e) {
            // expected
        }

        try {
            atlas.matches("/atlas/*sub");
            fail("Invalid FQAN group regexp was accepted");
        } catch (ParseException e) {
            // expected
        }

        try {
            atlas.matches("/atlas/sub*");
            fail("Invalid FQAN group regexp was accepted");
        } catch (ParseException e) {
            // expected
        }

        try {
            atlas.matches("/atlas/sub/**");
            fail("Invalid FQAN group regexp was accepted");
        } catch (ParseException e) {
            // expected
        }
        try {
            atlas.matches("/atlas/*/*");
            fail("Invalid FQAN group regexp was accepted");
        } catch (ParseException e) {
            // expected
        }

        try {
            atlas.matches("/atlas/*/sub");
            fail("Invalid FQAN group regexp was accepted");
        } catch (ParseException e) {
            // expected
        }

        try {
            atlas.matches("/atlas/Role=prod*");
            fail("Invalid FQAN role regexp was accepted");
        } catch (ParseException e) {
            // expected
        }

    }
    
    public void testEquals()throws ParseException {
        FQAN atlas = new FQAN("/atlas");
        assertTrue(atlas.equals(new FQAN("/atlas")));
        assertTrue(atlas.equals(new FQAN("/atlas/", FQAN.NULL, "null")));
        assertFalse(atlas.equals(new FQAN("/atlas/prod")));
        assertFalse(atlas.equals(new FQAN("/atlas", "sgm")));
    }
    
    public void testMatches() throws ParseException {
        FQAN atlas = new FQAN("/atlas");
        FQAN atlasProd = new FQAN("/atlas/prod");
        FQAN atlasRoleSGM = new FQAN("/atlas", "sgm");
        FQAN atlasProdRoleSGM = new FQAN("/atlas/prod", "sgm");
        FQAN atlassi = new FQAN("/atlassi");

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


        assertTrue(atlas.matches("/atlas/*"));
        assertTrue(atlasProd.matches("/atlas/*"));
        assertTrue(atlasProd.matches("/atlas/prod/*"));
        assertFalse(atlasRoleSGM.matches("/atlas/*"));
        assertFalse(atlasProdRoleSGM.matches("/atlas/*"));
        assertTrue(atlasProdRoleSGM.matches("/atlas/prod/*/Role=*"));
        assertFalse(atlassi.matches("/atlas/*"));

        assertFalse(atlas.matches("/atlas/*/Role=sgm"));
        assertFalse(atlasProd.matches("/atlas/*/Role=sgm"));
        assertTrue(atlasRoleSGM.matches("/atlas/*/Role=sgm"));
        assertFalse(atlassi.matches("/atlas/*/Role=sgm"));

        // BUG in FQAN: corrected
        assertFalse(atlasProdRoleSGM.matches("/atlas/*/Role=sgmXXX"));
        assertFalse(atlasProdRoleSGM.matches("/atlas/prod/Role=sgmXXX"));
        assertFalse(atlasRoleSGM.matches("/atlas/Role=sgmXXX"));
                
    }
    
}