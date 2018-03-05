package org.graylog.plugins.certificatetransparency.loginput;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.assistedinject.Assisted;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;

public class CertificateLogInput extends MessageInput {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateLogInput.class);

    private static final String NAME = "Certificate Transparency";

    @Inject
    public CertificateLogInput(@Assisted Configuration configuration,
                               MetricRegistry metricRegistry,
                               CertificateLogTransport.Factory transport,
                               LocalMetricRegistry localRegistry,
                               CertificateLogCodec.Factory codec,
                               Config config,
                               Descriptor descriptor,
                               ServerStatus serverStatus) {
        super(
                metricRegistry,
                configuration,
                transport.create(configuration),
                localRegistry,
                codec.create(configuration),
                config,
                descriptor,
                serverStatus
        );
    }

    @FactoryClass
    public interface Factory extends MessageInput.Factory<CertificateLogInput> {
        @Override
        CertificateLogInput create(Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    public static class Descriptor extends MessageInput.Descriptor {
        public Descriptor() {
            super(NAME, false, "");
        }
    }

    @ConfigClass
    public static class Config extends MessageInput.Config {
        @Inject
        public Config(CertificateLogTransport.Factory transport, CertificateLogCodec.Factory codec) {
            super(transport.getConfig(), codec.getConfig());
        }
    }

}
