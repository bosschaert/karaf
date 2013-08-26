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

import java.util.Arrays;
import java.util.Collections;

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

    }
}
