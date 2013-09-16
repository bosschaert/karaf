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
package org.apache.karaf.shell.security.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public class SecuredCommandConfigTransformerTest {
    @Test
    public void testTransformation() throws Exception {
        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put("foo", "a,b,c");
        props.put("bar[/.*[a]+*/]", "d");
        props.put("bar", "e");
        props.put("zar[/.*HiThere*/]", "f");

        Configuration commandConfig = EasyMock.createMock(Configuration.class);
        EasyMock.expect(commandConfig.getPid()).
            andReturn(SecuredCommandConfigTransformer.PROXY_COMMAND_ACL_PID_PREFIX + "abc").anyTimes();
        EasyMock.expect(commandConfig.getProperties()).andReturn(props).anyTimes();
        EasyMock.replay(commandConfig);

        final Map<String, Configuration> configurations = new HashMap<String, Configuration>();

        ConfigurationAdmin ca = EasyMock.createMock(ConfigurationAdmin.class);
        EasyMock.expect(ca.listConfigurations(
                "(service.pid=" + SecuredCommandConfigTransformer.PROXY_COMMAND_ACL_PID_PREFIX + "*)")).
                andReturn(new Configuration [] {commandConfig}).anyTimes();
        EasyMock.expect(ca.getConfiguration(EasyMock.isA(String.class))).andAnswer(new IAnswer<Configuration>() {
            @Override
            public Configuration answer() throws Throwable {
                String pid = (String) EasyMock.getCurrentArguments()[0];
                Configuration c = configurations.get(pid);
                if (c == null) {
                    c = EasyMock.createMock(Configuration.class);

                    // Put some expectations in the mock
                    if ("org.apache.karaf.service.acl.command.abc.foo".equals(pid)) {
                        Dictionary<String, Object> m = new Hashtable<String, Object>();
                        c.update(m);
                        EasyMock.expectLastCall().once();
                    } else {
                        fail("Unexpected PID: " + pid);
                    }


                    EasyMock.replay(c);
                    configurations.put(pid, c);
                }
                return c;
            }
        }).anyTimes();
        EasyMock.replay(ca);

        SecuredCommandConfigTransformer scct = new SecuredCommandConfigTransformer();
        scct.setConfigAdmin(ca);
        scct.init();

        assertEquals(3, configurations.size());

        boolean foundFoo = false;
        boolean foundBar = false;
        boolean foundZar = false;
        for (Map.Entry<String, Configuration> entry : configurations.entrySet()) {
            Configuration c = entry.getValue();
            EasyMock.verify(c);
            if ("org.apache.karaf.service.acl.command.abc.foo".equals(entry.getKey())) {
                foundFoo = true;
            }
        }

        assertTrue(foundFoo);
        assertTrue(foundBar);
        assertTrue(foundZar);

    }
}
