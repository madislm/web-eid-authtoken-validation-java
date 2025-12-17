package eu.webeid.security;

import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.net.URI;

public class RevocationInfoWithOcspResp extends RevocationInfo {

    private final OCSPResp ocspResp;

    public RevocationInfoWithOcspResp(URI ocspResponderUri, AuthTokenException exception, OCSPResp ocspResp) {
        super(ocspResponderUri, exception);
        this.ocspResp = ocspResp;
    }

    public RevocationInfoWithOcspResp(RevocationInfo revocationInfo, OCSPResp ocspResp) {
        super(revocationInfo.getOcspResponderUri(), revocationInfo.getException());
        this.ocspResp = ocspResp;
    }

    public OCSPResp getOcspResp() {
        return ocspResp;
    }
}
