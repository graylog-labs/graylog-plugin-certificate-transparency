package org.graylog.plugins.certificatetransparency.loginput.ct.logs.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateTransparencyEntryResponse {

    @JsonProperty("leaf_input")
    public String leafInput;

    @JsonProperty("extra_data")
    public String extraData;

}
