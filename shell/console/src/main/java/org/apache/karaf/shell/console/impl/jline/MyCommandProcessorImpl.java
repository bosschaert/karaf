package org.apache.karaf.shell.console.impl.jline;

import org.apache.felix.gogo.runtime.CommandProcessorImpl;
import org.apache.felix.service.threadio.ThreadIO;

public class MyCommandProcessorImpl extends CommandProcessorImpl {
    public MyCommandProcessorImpl(ThreadIO tio) {
        super(tio);
    }
}
