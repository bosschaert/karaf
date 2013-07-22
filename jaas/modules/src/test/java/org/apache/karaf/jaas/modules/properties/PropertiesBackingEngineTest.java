/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.karaf.jaas.modules.properties;


import junit.framework.TestCase;

import org.apache.felix.utils.properties.Properties;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.jaas.boot.principal.UserPrincipal;

public class PropertiesBackingEngineTest extends TestCase {

    public void testUserRoles() {
        Properties p = new Properties();

        PropertiesBackingEngine engine = new PropertiesBackingEngine(p);
        engine.addUser("a", "aa");
        assertEquals(1, engine.listUsers().size());
        UserPrincipal up = engine.listUsers().iterator().next();
        assertEquals("a", up.getName());

        engine.addRole("a", "role1");
        engine.addRole("a", "role2");
        assertEquals(2, engine.listRoles(up).size());

        boolean foundR1 = false;
        boolean foundR2 = false;
        for (RolePrincipal rp : engine.listRoles(up)) {
            if ("role1".equals(rp.getName())) {
                foundR1 = true;
            } else if ("role2".equals(rp.getName())) {
                foundR2 = true;
            }
        }
        assertTrue(foundR1);
        assertTrue(foundR2);

        engine.addGroup("a", "g");
        engine.addGroupRole("g", "role2");
        engine.addGroupRole("g", "role3");

        assertEquals(3, engine.listRoles(up).size());
        boolean foundR1_2 = false;
        boolean foundR2_2 = false;
        boolean foundR3_2 = false;
        for (RolePrincipal rp : engine.listRoles(up)) {
            if ("role1".equals(rp.getName())) {
                foundR1_2 = true;
            } else if ("role2".equals(rp.getName())) {
                foundR2_2 = true;
            } else if ("role3".equals(rp.getName())) {
                foundR3_2 = true;
            }
        }
        assertTrue(foundR1_2);
        assertTrue(foundR2_2);
        assertTrue(foundR3_2);
    }
}
