
package org.graylog.plugins.certificatetransparency.loginput;

import com.codahale.metrics.MetricSet;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.eventbus.EventBus;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.google.inject.assistedinject.Assisted;
import okhttp3.OkHttpClient;
import org.graylog.plugins.certificatetransparency.loginput.ct.logs.LogReader;
import org.graylog.plugins.certificatetransparency.loginput.ct.logservers.LogServer;
import org.graylog.plugins.certificatetransparency.loginput.ct.logservers.LogServers;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.MisfireException;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.CodecAggregator;
import org.graylog2.plugin.inputs.transports.ThrottleableTransport;
import org.graylog2.plugin.inputs.transports.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class CertificateLogTransport implements Transport {

    public static final String NAME = "CertificateTransparency";

    private static final Logger LOG = LoggerFactory.getLogger(CertificateLogTransport.class);

    private final ServerStatus serverStatus;
    private final URI httpProxyUri;
    private final LocalMetricRegistry localRegistry;
    private final ClusterConfigService clusterConfigService;
    private final ObjectMapper objectMapper;
    private final OkHttpClient httpClient;

    private final ScheduledExecutorService logServerRefreshService;
    private final ScheduledExecutorService logReaderService;

    private ImmutableList<LogServer> logServers = null;

    // A list of known broken servers that would just throw tons of exceptions.
    public static final ImmutableList<String> BAD_SERVERS = new ImmutableList.Builder<String>()
            .add("log.certly.io/") // NXDOMAIN
            .add("ct.izenpe.com/") // timeout
            .add("ct.izenpe.eus/") // timeout
            .add("ct.wosign.com/") // connection refused
            .add("ctlog.wosign.com/") // ssl handshake errors
            .add("ctlog2.wosign.com/") // NXDOMAIN
            .add("ct.gdca.com.cn/") // ssl handshake error
            .add("ctlog.gdca.com.cn/") // ssl handshake error
            .add("ctlog.api.venafi.com/") // NXDOMAIN
            .add("ct.startssl.com/") // ssl handshake error
            .add("www.certificatetransparency.cn/ct/") // timeout
            .add("flimsy.ct.nordu.net:8080/") // connection refused
            .add("ctlog.sheca.com/") // NXDOMAIN
            .add("ct.sheca.com/") // ssl handshake error
            .add("ct.akamai.com/") // ssl unverified peer
            .add("alpha.ctlogs.org/") // NXDOMAIN
            .add("clicky.ct.letsencrypt.org/") // NXDOMAIN
            .add("ct.filippo.io/behindthesofa/") // no route
            .build();

    @Inject
    public CertificateLogTransport(@Assisted final Configuration configuration,
                                   final ClusterConfigService clusterConfigService,
                                   final EventBus serverEventBus, final ObjectMapper objectMapper,
                                   final ServerStatus serverStatus,
                                   final OkHttpClient httpClient,
                                   @Named("http_proxy_uri") @Nullable URI httpProxyUri,
                                   LocalMetricRegistry localRegistry) {
        this.clusterConfigService = clusterConfigService;
        this.serverStatus = serverStatus;
        this.httpProxyUri = httpProxyUri;
        this.localRegistry = localRegistry;

        this.httpClient = httpClient.newBuilder()
                .followRedirects(true)
                .followSslRedirects(true)
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .build();

        this.objectMapper = objectMapper;
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        this.logServerRefreshService = Executors.newScheduledThreadPool(1,
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("ct-log-server-refresh-%d")
                        .build());

        this.logReaderService = Executors.newScheduledThreadPool(10,
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("ct-log-reader-%d")
                        .build());
    }

    @Override
    public void setMessageAggregator(CodecAggregator aggregator) {
        // Not supported.
    }

    @Override
    public void launch(MessageInput input) throws MisfireException {
        // Load log servers and start background job to keep updating.
        updateLogServers();
        this.logServerRefreshService.scheduleWithFixedDelay(this::updateLogServers, 1, 1, TimeUnit.HOURS);

        // Read latest logs every 5 seconds. // TODO make configurable
        final LogReader reader = new LogReader(input, httpClient, objectMapper, logServers);
        this.logReaderService.scheduleWithFixedDelay(reader::read, 0, 5, TimeUnit.SECONDS);
    }

    private void updateLogServers() {
        try {
            final LogServers logServersFetcher = new LogServers(objectMapper, httpClient, BAD_SERVERS);
            this.logServers = logServersFetcher.fetch();
        } catch (IOException | LogServers.FetchException e) {
            LOG.error("Could not refresh Certificate Transparency log servers.", e);
        }
    }

    private void readLogs() {

    }

    @Override
    public void stop() {
        this.logServerRefreshService.shutdown();
        this.logReaderService.shutdown();
    }

    @Override
    public MetricSet getMetricSet() {
        return localRegistry;
    }

    @FactoryClass
    public interface Factory extends Transport.Factory<CertificateLogTransport> {
        @Override
        CertificateLogTransport create(Configuration configuration);

        @Override
        Config getConfig();
    }

    @ConfigClass
    public static class Config extends ThrottleableTransport.Config {

        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest r = super.getRequestedConfiguration();

            return r;
        }

    }

}
