package org.graylog.plugins.certificatetransparency;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.Collections;

public class CertificateTransparencyPlugin implements Plugin {
    @Override
    public PluginMetaData metadata() {
        return new CertificateTransparencyPluginMetaData();
    }

    @Override
    public Collection<PluginModule> modules () {
        return Collections.<PluginModule>singletonList(new CertificateTransparencyPluginModule());
    }
}
