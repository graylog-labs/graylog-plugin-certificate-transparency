package org.graylog.plugins.certificatetransparency.loginput.ct.logs.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignedTreeHeadResponse {

    @JsonProperty("tree_size")
    public long treeSize;

}
