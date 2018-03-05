package org.graylog.plugins.certificatetransparency.loginput;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;
import com.google.inject.assistedinject.Assisted;
import info.debatty.java.stringsimilarity.Levenshtein;
import org.certificatetransparency.ctlog.ParsedLogEntry;
import org.certificatetransparency.ctlog.serialization.Deserializer;
import org.elasticsearch.common.Strings;
import org.graylog.plugins.certificatetransparency.loginput.ct.logs.json.CertificateTransparencyEntryResponse;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.inputs.codecs.Codec;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

public class CertificateLogCodec extends AbstractCodec {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateLogCodec.class);

    public static final String NAME = "CertificateLog";

    private final ObjectMapper om;
    private final Levenshtein levenshtein;

    @Inject
    public CertificateLogCodec(@Assisted Configuration configuration, ObjectMapper om) {
        super(configuration);

        this.om = om;
        this.levenshtein = new Levenshtein();
    }

    @Nullable
    @Override
    public Message decode(@Nonnull RawMessage rawMessage) {
        try {
            LOG.debug("Received Certificate Transparency log.");
            CertificateTransparencyEntryResponse log = om.readValue(rawMessage.getPayload(), CertificateTransparencyEntryResponse.class);

            try {
                ParsedLogEntry parsedLogEntry = Deserializer.parseLogEntry(
                        new ByteArrayInputStream(BaseEncoding.base64().decode(log.leafInput)),
                        new ByteArrayInputStream(BaseEncoding.base64().decode(log.extraData))
                );

                // The entry is either a pre-cert or an already issued X509 cert.
                if (parsedLogEntry.getLogEntry().x509Entry != null) {
                    X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(parsedLogEntry.getLogEntry().x509Entry.leafCertificate));

                    Map<String, Object> issuerFields = parseX500DataToFields(new LdapName(certificate.getIssuerX500Principal().toString()), "issuer");
                    Map<String, Object> subjectFields = parseX500DataToFields(new LdapName(certificate.getSubjectX500Principal().toString()), "subject");
                    String subjectCommonName = (String) subjectFields.get("ct_subject_common_name");

                    if (Strings.isNullOrEmpty(subjectCommonName)) {
                        LOG.error("Certificate Transparency entry is missing subject name (domain name). Skipping.");
                        return null;
                    }

                    Message message = new Message("[CT] Certificate for [" + subjectCommonName +"] issued", "certificate-transparency", DateTime.now());
                    message.addFields(issuerFields);
                    message.addFields(subjectFields);
                    message.addField("levenshtein_distance", levenshtein.distance("graylog.org", subjectCommonName));

                    return message;
                } else if(parsedLogEntry.getLogEntry().precertEntry != null) {
                    LOG.warn("UNSUPPORTED PRECERT RECEIVED."); // TODO
                } else {
                    LOG.error("Certificate Transparency entry is not a pre-cert or an issued X509. Skipping.");
                    return null;
                }
            } catch(Exception e) {
                LOG.error("Could not decode Certificate Transparency entry.", e);
                return null;
            }

            return null;
        } catch (Exception e) {
            throw new RuntimeException("Could not deserialize Certificate Transparency log.", e);
        }
    }

    private Map<String, Object> parseX500DataToFields(LdapName dn, String prefix) {
        ImmutableMap.Builder<String, Object> fields = new ImmutableMap.Builder<>();
        for (Rdn issuer : dn.getRdns()) {
            switch(issuer.getType()) {
                case "CN": // common_name
                    fields.put("ct_" + prefix + "_common_name", issuer.getValue().toString());
                    break;
                case "C": // country
                    fields.put("ct_" + prefix + "_country", issuer.getValue().toString());
                    break;
                case "O": // organization
                    fields.put("ct_" + prefix + "_organization", issuer.getValue().toString());
                    break;
                case "OU": // organizational_unit
                    fields.put("ct_" + prefix + "_organizational_unit", issuer.getValue().toString());
                    break;
            }
        }

        return fields.build();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @FactoryClass
    public interface Factory extends Codec.Factory<CertificateLogCodec> {
        @Override
        CertificateLogCodec create(Configuration configuration);

        @Override
        Config getConfig();
    }

    @ConfigClass
    public static class Config extends AbstractCodec.Config {
    }

}
