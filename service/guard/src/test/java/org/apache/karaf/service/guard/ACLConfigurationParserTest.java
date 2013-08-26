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
package org.apache.karaf.service.guard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;

import org.apache.karaf.service.guard.tools.ACLConfigurationParser;
import org.junit.Test;

public class ACLConfigurationParserTest {
    @Test
    public void testParseRoles() {
        assertEquals(Arrays.asList("some_role"),
                ACLConfigurationParser.parseRoles(" some_role   "));
        assertEquals(Arrays.asList("a","b","C"),
                ACLConfigurationParser.parseRoles("a,b,C"));
        assertEquals(Collections.emptyList(),
                ACLConfigurationParser.parseRoles("# test comment"));
    }

    @Test
    public void testGetRolesForInvocation() {
        Dictionary<String, Object> config = new Hashtable<String, Object>();
        config.put("foo", "r1, r2");
        config.put("bar(java.lang.String, int)[/aa/,/42/]", "ra");
        config.put("bar(java.lang.String, int)[/bb/,/42/]", "rb");
        config.put("bar(java.lang.String, int)[\"cc\", \"17\"]", "rc");
        config.put("bar(java.lang.String, int)", "rd");
        config.put("bar(java.lang.String)", "re");
        config.put("bar", "rf");

        assertEquals(Arrays.asList("r1", "r2"), ACLConfigurationParser.getRolesForInvocation(
                "foo", new Object [] {}, new String [] {}, config));
        assertEquals(Arrays.asList("r1", "r2"), ACLConfigurationParser.getRolesForInvocation(
                "foo", new Object [] {"test"}, new String [] {"java.lang.String"}, config));
        assertNull(ACLConfigurationParser.getRolesForInvocation(
                "test", new Object [] {}, new String [] {}, config));
        assertEquals(Arrays.asList("ra"), ACLConfigurationParser.getRolesForInvocation(
                "bar", new Object [] {"aa", 42}, new String [] {"java.lang.String", "int"}, config));
        assertEquals(Arrays.asList("rb"), ACLConfigurationParser.getRolesForInvocation(
                "bar", new Object [] {"bb", 42}, new String [] {"java.lang.String", "int"}, config));
        assertEquals(Arrays.asList("rc"), ACLConfigurationParser.getRolesForInvocation(
                "bar", new Object [] {"cc", 17}, new String [] {"java.lang.String", "int"}, config));
        assertEquals(Arrays.asList("rd"), ACLConfigurationParser.getRolesForInvocation(
                "bar", new Object [] {"aaa", 42}, new String [] {"java.lang.String", "int"}, config));
        assertEquals(Arrays.asList("re"), ACLConfigurationParser.getRolesForInvocation(
                "bar", new Object [] {"aa"}, new String [] {"java.lang.String"}, config));
        assertEquals(Arrays.asList("rf"), ACLConfigurationParser.getRolesForInvocation(
                "bar", new Object [] {42}, new String [] {"int"}, config));
    }
}
