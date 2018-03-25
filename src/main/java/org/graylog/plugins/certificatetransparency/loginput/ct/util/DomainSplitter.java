package org.graylog.plugins.certificatetransparency.loginput.ct.util;

import com.google.common.collect.Maps;

import java.util.Map;

public class DomainSplitter {

    public static Map<String, String> split(String domain, String prefix) {
        if (!domain.contains(".")) {
            throw new IllegalArgumentException("Invalid domain [" + domain + "].");
        }

        Map<String, String> result = Maps.newHashMap();

        String[] levels = domain.split("\\.");
        String l1 = levels[levels.length-1];
        String l2 = levels[levels.length-2];
        result.put("ct_" + prefix + "_common_name", domain);
        result.put("ct_" + prefix + "_common_name_l1", l1);
        result.put("ct_" + prefix + "_common_name_l2", l2);
        result.put("ct_" + prefix + "_common_name_l12", l2 + "." + l1);

        return result;
    }

}
