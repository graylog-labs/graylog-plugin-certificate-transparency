package org.graylog.plugins.certificatetransparency.loginput.ct.logs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.graylog.plugins.certificatetransparency.loginput.ct.logs.json.CertificateTransparencyEntryResponse;
import org.graylog.plugins.certificatetransparency.loginput.ct.logs.json.EntriesListResponse;
import org.graylog.plugins.certificatetransparency.loginput.ct.logs.json.SignedTreeHeadResponse;
import org.graylog.plugins.certificatetransparency.loginput.ct.logservers.LogServer;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.journal.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class LogReader {

    private static final Logger LOG = LoggerFactory.getLogger(LogReader.class);

    private final static int CHUNK_SIZE = 64;

    private final MessageInput input;
    private final OkHttpClient httpClient;
    private final ObjectMapper om;

    private final ImmutableList<LogServer> logServers;

    private final Map<LogServer, Long> lastPositions;

    public LogReader(MessageInput input, OkHttpClient httpClient, ObjectMapper om, ImmutableList<LogServer> logServers) {
        this.input = input;
        this.httpClient = httpClient;
        this.om = om;

        this.logServers = logServers;
        this.lastPositions = Maps.newHashMap();
    }

    public void read() {
        for (LogServer logServer : this.logServers) {
            try {
                LOG.debug("Reading Certificate Transparency logs from [{}].", logServer);

                HttpUrl url = HttpUrl.parse("https://" + logServer.url());

                if (url == null) {
                    LOG.warn("Skipping Certificate Transparency log server with invalid URL: [{}].", logServer);
                    continue;
                }

                Long treeSize = getTreeSize(url);
                Long previousTreeSize = lastPositions.get(logServer);

                lastPositions.put(logServer, treeSize);
                if(previousTreeSize == null) {
                    // Don't run on first run. Wait for next run, when we have a previous position to compare.
                    LOG.debug("Skipping first run on [{}].", logServer);
                    lastPositions.put(logServer, treeSize);
                } else {
                    // Read everything since last run, in chunks.
                    long diff = treeSize-previousTreeSize;

                    if (diff > 0) {
                        LOG.debug("Fetching {} [{}->{}] new entries from [{}].", diff, previousTreeSize, treeSize, logServer);

                        for (CertificateTransparencyEntryResponse entry : getNewEntries(url, previousTreeSize, treeSize)) {
                            input.processRawMessage(new RawMessage(om.writeValueAsBytes(entry)));
                        }
                    }
                }
            } catch(Exception e) {
                LOG.error("Could not read logs from [{}]. Skipping.", logServer, e);
            }
        }

        LOG.debug("Certificate Transparency read run finished successfully.");
    }

    private long getTreeSize(HttpUrl url) throws IOException {
        Response response = httpClient.newCall(new Request.Builder()
                .get()
                .url(url.newBuilder().addEncodedPathSegments("ct/v1/get-sth").build())
                .build()
        ).execute();

        try {
            if (response.code() != 200) {
                throw new RuntimeException("Expected HTTP response code <200> but got <" + response.code() + ">");
            }

            String body = response.body().string();

            SignedTreeHeadResponse sth = om.readValue(body, SignedTreeHeadResponse.class);
            return sth.treeSize;
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    private List<CertificateTransparencyEntryResponse> getNewEntries(HttpUrl url, Long from, Long to) throws IOException {
        Response response = httpClient.newCall(new Request.Builder()
                .get()
                .url(url.newBuilder()
                        .addEncodedPathSegments("ct/v1/get-entries")
                        .addQueryParameter("start", from.toString())
                        .addQueryParameter("end", to.toString())
                        .build())
                .build()
        ).execute();

        try {
            if (response.code() != 200) {
                throw new RuntimeException("Expected HTTP response code <200> but got <" + response.code() + ">");
            }

            String body = response.body().string();

            EntriesListResponse entries = om.readValue(body, EntriesListResponse.class);
            return entries.entries;
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

}
