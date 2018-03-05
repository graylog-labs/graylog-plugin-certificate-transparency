package org.graylog.plugins.certificatetransparency.loginput.ct.logservers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.graylog.plugins.certificatetransparency.loginput.ct.logservers.json.LogServerResponse;
import org.graylog.plugins.certificatetransparency.loginput.ct.logservers.json.LogServersListResponse;
import org.graylog.plugins.certificatetransparency.loginput.ct.logservers.json.OperatorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

public class LogServers {

    private static final Logger LOG = LoggerFactory.getLogger(LogServers.class);

    public static final String ALL_LOGS_LIST = "https://www.gstatic.com/ct/log_list/all_logs_list.json";

    private final ObjectMapper om;
    private final OkHttpClient httpClient;

    private final ImmutableList<String> badServers;

    public LogServers(ObjectMapper om, OkHttpClient httpClient, ImmutableList<String> badServers) {
        this.om = om;
        this.httpClient = httpClient;

        this.badServers = badServers;
    }

    public ImmutableList<LogServer> fetch() throws IOException, FetchException {
        LOG.info("Fetching current list of Certificate Transparency log servers.");
        ImmutableList.Builder<LogServer> servers = new ImmutableList.Builder<>();

        Response response = this.httpClient.newCall(
                new Request.Builder()
                        .get()
                        .url(ALL_LOGS_LIST)
                        .build()
        ).execute();

        try {
            if (response.code() != 200) {
                throw new FetchException("Expected HTTP response code <200> but got <" + response.code() + ">");
            }

            String body = response.body().string();

            LogServersListResponse list = om.readValue(body, LogServersListResponse.class);
            for (LogServerResponse rawLog : list.logs) {
                // Find operators of this log.
                ImmutableList.Builder<String> operators = new ImmutableList.Builder<>();
                for (Long operatorId : rawLog.operatedBy) {
                    operators.add(findOperatorName(operatorId, list.operators));
                }

                if(badServers.contains(rawLog.url)) {
                    LOG.debug("Skipping known broken CT server [{}].", rawLog.url);
                    continue;
                }

                servers.add(LogServer.create(
                        rawLog.description,
                        rawLog.url,
                        operators.build()
                ));
            }

            return servers.build();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    private String findOperatorName(Long id, List<OperatorResponse> operators) {
        for (OperatorResponse operator : operators) {
            if (id.equals(operator.id)) {
               return operator.name;
            }
        }

        return "UNKNOWN";
    }

    public class FetchException extends Exception {

        FetchException(String msg) {
            super(msg);
        }

    }
}
