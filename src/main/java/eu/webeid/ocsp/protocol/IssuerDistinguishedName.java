package eu.webeid.ocsp.protocol;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;

public class IssuerDistinguishedName {

    public static Optional<X500Name> getIssuerDistinguishedName(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        String issuerDN = certificate.getIssuerX500Principal().getName();
        if (issuerDN.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new X500Name(issuerDN));
    }

    private IssuerDistinguishedName() {
        throw new IllegalStateException("Utility class");
    }
}
