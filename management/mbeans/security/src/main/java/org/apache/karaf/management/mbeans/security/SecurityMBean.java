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
package org.apache.karaf.management.mbeans.security;

import java.util.List;
import java.util.Map;

import javax.management.MalformedObjectNameException;
import javax.management.openmbean.TabularData;


/**
 * Security MBean
 */
public interface SecurityMBean {
    /**
     * Checks whether the current user can invoke any methods on a JMX MBean.
     * @param objectName The Object Name of the JMX MBean.
     * @return {@code true} if there is at least one method on the MBean that the
     * user can invoke.
     * @throws MalformedObjectNameException
     * @throws Exception
     */
    boolean canInvoke(String objectName) throws Exception;

    /**
     * Checks whether the current user can invoke the given method.
     * @param objectName The Object Name of the JMX MBean.
     * @param methodName The name of the method to check.
     * @param argumentTypes The argument types of te method.
     * @return {@code true} if the user is allowed to invoke the method. There may still
     * be certain values that the user does not have permission to pass to the method.
     */
    boolean canInvoke(String objectName, String methodName, String [] argumentTypes) throws Exception;

    TabularData canInvoke(Map<String, List<String>> query) throws Exception;
}
