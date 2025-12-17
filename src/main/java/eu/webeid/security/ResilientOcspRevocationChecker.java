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

package eu.webeid.security;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
import eu.webeid.security.exceptions.UserCertificateUnknownException;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspRequestBuilder;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.OcspService;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.decorators.Decorators;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import io.vavr.CheckedFunction0;
import io.vavr.control.Try;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class ResilientOcspRevocationChecker implements OcspCertificateRevocationChecker {
    private static final Logger LOG = LoggerFactory.getLogger(ResilientOcspRevocationChecker.class);

    private final OcspClient ocspClient;
    private final OcspServiceProvider ocspServiceProvider;
    private final Duration allowedOcspResponseTimeSkew;
    private final Duration maxOcspResponseThisUpdateAge;
    private final boolean rejectUnknownOcspResponseStatus;
    private final CircuitBreakerRegistry circuitBreakerRegistry;
    private final RetryRegistry retryRegistry;

    public ResilientOcspRevocationChecker(OcspClient ocspClient, OcspServiceProvider ocspServiceProvider, CircuitBreakerConfig circuitBreakerConfig, RetryConfig retryConfig, Duration allowedOcspResponseTimeSkew, Duration maxOcspResponseThisUpdateAge, boolean rejectUnknownOcspResponseStatus) {
        this.ocspClient = ocspClient;
        this.ocspServiceProvider = ocspServiceProvider;
        this.allowedOcspResponseTimeSkew = allowedOcspResponseTimeSkew;
        this.maxOcspResponseThisUpdateAge = maxOcspResponseThisUpdateAge;
        this.rejectUnknownOcspResponseStatus = rejectUnknownOcspResponseStatus;
        this.circuitBreakerRegistry = CircuitBreakerRegistry.custom()
            .withCircuitBreakerConfig(getCircuitBreakerConfig(circuitBreakerConfig))
            .build();
        this.retryRegistry = retryConfig != null ? RetryRegistry.custom()
            .withRetryConfig(getRetryConfigConfig(retryConfig))
            .build() : null;
        if (!LOG.isDebugEnabled()) {
            return;
        }
        this.circuitBreakerRegistry.getEventPublisher()
            .onEntryAdded(entryAddedEvent -> {
                CircuitBreaker circuitBreaker = entryAddedEvent.getAddedEntry();
                LOG.debug("CircuitBreaker {} added", circuitBreaker.getName());
                circuitBreaker.getEventPublisher()
                    .onEvent(event -> LOG.debug(event.toString()));
            });
    }

    @Override
    public Iterable<RevocationInfo> validate(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws AuthTokenException {
        OcspService ocspService;
        try {
            ocspService = ocspServiceProvider.getService(subjectCertificate);
        } catch (CertificateException e) {
            throw new UserCertificateOCSPCheckFailedException(e, new ValidationInfo(subjectCertificate, null));
        }
        final OcspService fallbackOcspService = ocspService.getFallbackService();
        if (fallbackOcspService == null) {
            return Collections.singleton(request(ocspService, subjectCertificate, issuerCertificate));
        }

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(ocspService.getAccessLocation().toASCIIString());
        CheckedFunction0<RevocationInfo> primarySupplier = () -> request(ocspService, subjectCertificate, issuerCertificate);
        CheckedFunction0<RevocationInfo> fallbackSupplier = () -> request(ocspService.getFallbackService(), subjectCertificate, issuerCertificate);
        Decorators.DecorateCheckedSupplier<RevocationInfo> decorateCheckedSupplier = Decorators.ofCheckedSupplier(primarySupplier);
        if (retryRegistry != null) {
            Retry retry = retryRegistry.retry(ocspService.getAccessLocation().toASCIIString());
            decorateCheckedSupplier.withRetry(retry);
        }
        decorateCheckedSupplier.withCircuitBreaker(circuitBreaker)
            .withFallback(List.of(UserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class, UserCertificateUnknownException.class), e -> fallbackSupplier.apply());

        CheckedFunction0<RevocationInfo> decoratedSupplier = decorateCheckedSupplier.decorate();

        // TODO Collect the intermediate results
        return Collections.singleton(Try.of(decoratedSupplier).getOrElseThrow(throwable -> {
            if (throwable instanceof AuthTokenException) {
                return (AuthTokenException) throwable;
            }
            return new UserCertificateOCSPCheckFailedException(throwable);
        }));
    }

    private RevocationInfoWithOcspResp request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws AuthTokenException {
        OCSPResp response = null;
        try {
            final CertificateID certificateId = OcspResponseValidator.getCertificateId(subjectCertificate, issuerCertificate);
            final OCSPReq request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            response = Objects.requireNonNull(ocspClient.request(ocspService.getAccessLocation(), request)); // TODO: This should trigger fallback?
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                UserCertificateOCSPCheckFailedException exception = new UserCertificateOCSPCheckFailedException("Response status: " + OcspResponseValidator.ocspStatusToString(response.getStatus()));
                RevocationInfoWithOcspResp revocationInfoWithOcspResp = new RevocationInfoWithOcspResp(ocspService.getAccessLocation(), exception, response);
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, Collections.singleton(revocationInfoWithOcspResp)));
                throw exception;
            }

            final Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            RevocationInfo revocationInfo = OcspResponseValidator.verifyOcspResponse(response, ocspService,
                requestNonce, subjectCertificate, issuerCertificate, allowedOcspResponseTimeSkew,
                maxOcspResponseThisUpdateAge, rejectUnknownOcspResponseStatus);
            RevocationInfoWithOcspResp revocationInfoWithOcspResp = new RevocationInfoWithOcspResp(
                revocationInfo,
                response
            );
            LOG.debug("OCSP check result is GOOD");

            return revocationInfoWithOcspResp;
        } catch (OCSPException | CertificateException | OperatorCreationException | IOException e) {
            UserCertificateOCSPCheckFailedException exception = new UserCertificateOCSPCheckFailedException(e);
            RevocationInfo revocationInfo = new RevocationInfoWithOcspResp(ocspService.getAccessLocation(), exception, response);
            exception.setValidationInfo(new ValidationInfo(subjectCertificate, Collections.singleton(revocationInfo)));
            throw exception;
        }
    }

    private static CircuitBreakerConfig getCircuitBreakerConfig(CircuitBreakerConfig circuitBreakerConfig) {
        return CircuitBreakerConfig.from(circuitBreakerConfig)
            // Users must not be able to modify these three values.
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .ignoreExceptions(UserCertificateRevokedException.class)
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .build();
    }

    private static RetryConfig getRetryConfigConfig(RetryConfig retryConfig) {
        return RetryConfig.from(retryConfig)
            // Users must not be able to modify this value.
            .ignoreExceptions(UserCertificateRevokedException.class)
            .build();
    }

    CircuitBreakerRegistry getCircuitBreakerRegistry() {
        return circuitBreakerRegistry;
    }
}
