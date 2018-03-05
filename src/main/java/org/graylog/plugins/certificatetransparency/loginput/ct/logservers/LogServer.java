package org.graylog.plugins.certificatetransparency.loginput.ct.logservers;

import com.google.auto.value.AutoValue;

import java.util.List;

@AutoValue
public abstract class LogServer {

    public abstract String description();
    public abstract String url();
    public abstract List<String> operatedBy();

    public static LogServer create(String description, String url, List<String> operatedBy) {
        return builder()
                .description(description)
                .url(url)
                .operatedBy(operatedBy)
                .build();
    }

    public static Builder builder() {
        return new AutoValue_LogServer.Builder();
    }

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder description(String description);

        public abstract Builder url(String url);

        public abstract Builder operatedBy(List<String> operatedBy);

        public abstract LogServer build();
    }

}
