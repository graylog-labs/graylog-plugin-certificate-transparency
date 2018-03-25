package org.graylog.plugins.certificatetransparency.loginput.ct.util;

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;

public class DomainSplitterTest {

    @Test
    public void splitDomain1() {
        Map<String, String> result = DomainSplitter.split("foo.example.org", "subject");
        assertEquals(4, result.size());
        assertEquals("foo.example.org", result.get("ct_subject_common_name"));
        assertEquals("example.org", result.get("ct_subject_common_name_l12"));
        assertEquals("example", result.get("ct_subject_common_name_l2"));
        assertEquals("org", result.get("ct_subject_common_name_l1"));
    }

    @Test
    public void splitDomain2() {
        Map<String, String> result = DomainSplitter.split("example.com", "subject");
        assertEquals(4, result.size());
        assertEquals("example.com", result.get("ct_subject_common_name"));
        assertEquals("example.com", result.get("ct_subject_common_name_l12"));
        assertEquals("example", result.get("ct_subject_common_name_l2"));
        assertEquals("com", result.get("ct_subject_common_name_l1"));
    }

    @Test
    public void splitDomain3() {
        Map<String, String> result = DomainSplitter.split("foo.bar.example.net", "subject");
        assertEquals(4, result.size());
        assertEquals("foo.bar.example.net", result.get("ct_subject_common_name"));
        assertEquals("example.net", result.get("ct_subject_common_name_l12"));
        assertEquals("example", result.get("ct_subject_common_name_l2"));
        assertEquals("net", result.get("ct_subject_common_name_l1"));
    }

    @Test
    public void testPrefix() {
        Map<String, String> result = DomainSplitter.split("foo.example.org", "something");
        assertEquals(4, result.size());
        assertEquals("foo.example.org", result.get("ct_something_common_name"));
        assertEquals("example.org", result.get("ct_something_common_name_l12"));
        assertEquals("example", result.get("ct_something_common_name_l2"));
        assertEquals("org", result.get("ct_something_common_name_l1"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void splitInvalidDoain() {
        DomainSplitter.split("notadomain", "subject");
    }

}