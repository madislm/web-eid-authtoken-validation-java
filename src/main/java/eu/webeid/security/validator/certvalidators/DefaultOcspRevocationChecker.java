/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.OcspCertificateRevocationChecker;
import eu.webeid.security.RevocationInfo;
import eu.webeid.security.ValidationInfo;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspRequestBuilder;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.OcspService;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.Objects;

public final class DefaultOcspRevocationChecker implements OcspCertificateRevocationChecker {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOcspRevocationChecker.class);

    private final OcspClient ocspClient;
    private final OcspServiceProvider ocspServiceProvider;
    private final Duration allowedOcspResponseTimeSkew;
    private final Duration maxOcspResponseThisUpdateAge;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public DefaultOcspRevocationChecker(OcspClient ocspClient,
                                        OcspServiceProvider ocspServiceProvider,
                                        Duration allowedOcspResponseTimeSkew,
                                        Duration maxOcspResponseThisUpdateAge) {
        this.ocspClient = ocspClient;
        this.ocspServiceProvider = ocspServiceProvider;
        this.allowedOcspResponseTimeSkew = allowedOcspResponseTimeSkew;
        this.maxOcspResponseThisUpdateAge = maxOcspResponseThisUpdateAge;
    }

    /**
     * Validates that the user certificate from the authentication token is not revoked with OCSP.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when user certificate is revoked or revocation check fails.
     */
    @Override
    public Iterable<RevocationInfo> validate(X509Certificate subjectCertificate,
                                   X509Certificate issuerCertificate) throws AuthTokenException {
        OcspService ocspService = null;
        OCSPResp response = null;
        try {
            ocspService = ocspServiceProvider.getService(subjectCertificate);
            final CertificateID certificateId = OcspResponseValidator.getCertificateId(subjectCertificate, issuerCertificate);

            final OCSPReq request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            response = Objects.requireNonNull(ocspClient.request(ocspService.getAccessLocation(), request));
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw new UserCertificateOCSPCheckFailedException("Response status: " + OcspResponseValidator.ocspStatusToString(response.getStatus()));
            }

            final Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            RevocationInfo revocationInfo = OcspResponseValidator.verifyOcspResponse(response, ocspService,
                requestNonce, subjectCertificate, issuerCertificate, allowedOcspResponseTimeSkew,
                maxOcspResponseThisUpdateAge, false, false);
            LOG.debug("OCSP check result is GOOD");

            return Collections.singleton(revocationInfo);
        } catch (OCSPException | CertificateException | OperatorCreationException | IOException e) {
            URI ocspResponderUri = (ocspService != null)
                ? ocspService.getAccessLocation()
                : null;
            UserCertificateOCSPCheckFailedException exception = new UserCertificateOCSPCheckFailedException(e);
            RevocationInfo revocationInfo = new RevocationInfo(ocspResponderUri, exception);
            exception.setValidationInfo(new ValidationInfo(subjectCertificate, Collections.singleton(revocationInfo)));
            throw exception;
        }
    }

}
