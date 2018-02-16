package org.graylog.plugins.certificatetransparency;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

public class CertificateTransparencyPluginMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "org.graylog.graylog-plugin-certificate-transparency/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.certificatetransparency.CertificateTransparencyPlugin";
    }

    @Override
    public String getName() {
        return "Certificate Transparency Plugin";
    }

    @Override
    public String getAuthor() {
        return "Graylog, Inc <hello@graylog.com>";
    }

    @Override
    public URI getURL() {
        return URI.create("https://github.com/graylog-labs/graylog-plugin-certificate-transparency");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 0, 1));
    }

    @Override
    public String getDescription() {
        return "Plugin for interaction with Certificate Transparency APIs (https://www.certificate-transparency.org/)";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(2, 4, 0));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
