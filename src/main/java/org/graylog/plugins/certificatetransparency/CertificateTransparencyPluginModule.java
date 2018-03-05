package org.graylog.plugins.certificatetransparency;

import org.graylog.plugins.certificatetransparency.loginput.CertificateLogCodec;
import org.graylog.plugins.certificatetransparency.loginput.CertificateLogInput;
import org.graylog.plugins.certificatetransparency.loginput.CertificateLogTransport;
import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

import java.util.Collections;
import java.util.Set;

public class CertificateTransparencyPluginModule extends PluginModule {

    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
        addCodec(CertificateLogCodec.NAME, CertificateLogCodec.class);
        addTransport(CertificateLogTransport.NAME, CertificateLogTransport.class);
        addMessageInput(CertificateLogInput.class);
    }

}
