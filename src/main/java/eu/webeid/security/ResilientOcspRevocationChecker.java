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
import eu.webeid.security.exceptions.OcspClientException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
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
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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
    public List<RevocationInfo> validate(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws AuthTokenException {
        OcspService ocspService;
        try {
            ocspService = ocspServiceProvider.getService(subjectCertificate);
        } catch (CertificateException e) {
            throw new TaraUserCertificateOCSPCheckFailedException(e, new ValidationInfo(subjectCertificate, List.of()));
        }
        final OcspService fallbackOcspService = ocspService.getFallbackService();
        if (fallbackOcspService == null) {
            return List.of(request(ocspService, subjectCertificate, issuerCertificate, false));
        }

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(ocspService.getAccessLocation().toASCIIString());

        List<RevocationInfo> revocationInfoList = new ArrayList<>();
        circuitBreaker.getEventPublisher().onError(event -> {
           Throwable throwable = event.getThrowable();
           if (throwable instanceof TaraUserCertificateOCSPCheckFailedException) {
               revocationInfoList.addAll(((TaraUserCertificateOCSPCheckFailedException) throwable).getValidationInfo().getRevocationInfoList());
               return;
           }
           revocationInfoList.add(new RevocationInfo(null, Map.ofEntries(
               Map.entry(RevocationInfo.KEY_OCSP_ERROR, throwable)
           )));
        });

        CheckedFunction0<RevocationInfo> primarySupplier = () -> request(ocspService, subjectCertificate, issuerCertificate, false);
        OcspService firstFallbackService = ocspService.getFallbackService();
        CheckedFunction0<RevocationInfo> firstFallbackSupplier = () -> request(ocspService.getFallbackService(), subjectCertificate, issuerCertificate, true);
        OcspService secondFallbackService = ocspServiceProvider.getFallbackService(firstFallbackService.getAccessLocation());
        CheckedFunction0<RevocationInfo> fallbackSupplier;
        if (secondFallbackService == null) {
            fallbackSupplier = firstFallbackSupplier;
        } else {
            CheckedFunction0<RevocationInfo> secondFallbackSupplier = () -> request(secondFallbackService, subjectCertificate, issuerCertificate, true);
            fallbackSupplier = () -> {
                try {
                    return firstFallbackSupplier.apply();
                } catch (Exception e) {
                    if (e instanceof TaraUserCertificateOCSPCheckFailedException) {
                        revocationInfoList.addAll(((TaraUserCertificateOCSPCheckFailedException) e).getValidationInfo().getRevocationInfoList());
                    } else {
                        revocationInfoList.add(new RevocationInfo(null, Map.ofEntries(
                            Map.entry(RevocationInfo.KEY_OCSP_ERROR, e)
                        )));
                    }
                    return secondFallbackSupplier.apply();
                }
            };
        }
        Decorators.DecorateCheckedSupplier<RevocationInfo> decorateCheckedSupplier = Decorators.ofCheckedSupplier(primarySupplier);
        if (retryRegistry != null) {
            Retry retry = retryRegistry.retry(ocspService.getAccessLocation().toASCIIString());
            retry.getEventPublisher().onError(event -> {
                Throwable throwable = event.getLastThrowable();
                if (throwable == null) {
                    return;
                }
                if (throwable instanceof TaraUserCertificateOCSPCheckFailedException) {
                    revocationInfoList.addAll(((TaraUserCertificateOCSPCheckFailedException) throwable).getValidationInfo().getRevocationInfoList());
                    return;
                }
                revocationInfoList.add(new RevocationInfo(null, Map.ofEntries(
                    Map.entry(RevocationInfo.KEY_OCSP_ERROR, throwable)
                )));
            });
            decorateCheckedSupplier.withRetry(retry);
        }
        decorateCheckedSupplier.withCircuitBreaker(circuitBreaker)
            .withFallback(List.of(TaraUserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class), e -> fallbackSupplier.apply());

        CheckedFunction0<RevocationInfo> decoratedSupplier = decorateCheckedSupplier.decorate();

        Try<RevocationInfo> result = Try.of(decoratedSupplier);

        RevocationInfo revocationInfo = result.getOrElseThrow(throwable -> {
            if (throwable instanceof TaraUserCertificateOCSPCheckFailedException) {
                TaraUserCertificateOCSPCheckFailedException exception = (TaraUserCertificateOCSPCheckFailedException) throwable;
                revocationInfoList.addAll(exception.getValidationInfo().getRevocationInfoList());
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, revocationInfoList));
                return exception;
            }
            if (throwable instanceof TaraUserCertificateRevokedException) {
                TaraUserCertificateRevokedException exception = (TaraUserCertificateRevokedException) throwable;
                revocationInfoList.addAll(exception.getValidationInfo().getRevocationInfoList());
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, revocationInfoList));
                return exception;
            }
            // TODO This should always be TaraUserCertificateOCSPCheckFailedException when reached?
            return new TaraUserCertificateOCSPCheckFailedException(throwable, new ValidationInfo(subjectCertificate, revocationInfoList));
        });

        revocationInfoList.add(revocationInfo);
        return revocationInfoList;
    }

    private RevocationInfo request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate, boolean allowThisUpdateInPast) throws TaraUserCertificateOCSPCheckFailedException, TaraUserCertificateRevokedException {
        OCSPResp response = null;
        OCSPReq request = null;
        try {
            final CertificateID certificateId = OcspResponseValidator.getCertificateId(subjectCertificate, issuerCertificate);
            request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            response = Objects.requireNonNull(ocspClient.request(ocspService.getAccessLocation(), request)); // TODO: This should trigger fallback?
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                TaraUserCertificateOCSPCheckFailedException exception = new TaraUserCertificateOCSPCheckFailedException("Response status: " + OcspResponseValidator.ocspStatusToString(response.getStatus()));
                RevocationInfo revocationInfo = new RevocationInfo(ocspService.getAccessLocation(), Map.ofEntries(
                    Map.entry(RevocationInfo.KEY_OCSP_ERROR, exception),
                    Map.entry(RevocationInfo.KEY_OCSP_REQUEST, request),
                    Map.entry(RevocationInfo.KEY_OCSP_RESPONSE, response)
                ));
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
                throw exception;
            }

            final Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            OcspResponseValidator.verifyOcspResponse(response, ocspService,
                requestNonce, subjectCertificate, issuerCertificate, allowedOcspResponseTimeSkew,
                maxOcspResponseThisUpdateAge, rejectUnknownOcspResponseStatus, allowThisUpdateInPast);
            LOG.debug("OCSP check result is GOOD");

            return new RevocationInfo(ocspService.getAccessLocation(), Map.ofEntries(
                Map.entry(RevocationInfo.KEY_OCSP_REQUEST, request),
                Map.entry(RevocationInfo.KEY_OCSP_RESPONSE, response)
            ));
        } catch (UserCertificateRevokedException e) {
            RevocationInfo revocationInfo = getRevocationInfo(ocspService.getAccessLocation(), e, request, response);
            throw new TaraUserCertificateRevokedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        } catch (OcspClientException e) {
            RevocationInfo revocationInfo = getRevocationInfo(ocspService.getAccessLocation(), e, request, response);
            revocationInfo.getOcspResponseAttributes().put(RevocationInfo.KEY_OCSP_RESPONSE, e.getResponseBody());
            revocationInfo.getOcspResponseAttributes().put(RevocationInfo.KEY_HTTP_STATUS_CODE, e.getStatusCode());
            throw new TaraUserCertificateOCSPCheckFailedException(e, new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        } catch (Exception e) {
            RevocationInfo revocationInfo = getRevocationInfo(ocspService.getAccessLocation(), e, request, response);
            throw new TaraUserCertificateOCSPCheckFailedException(e, new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        }
    }

    private RevocationInfo getRevocationInfo(URI ocspResponderUri, Exception e, OCSPReq request, OCSPResp response) {
        RevocationInfo revocationInfo = new RevocationInfo(ocspResponderUri, new HashMap<>(Map.of(RevocationInfo.KEY_OCSP_ERROR, e)));
        if (request != null) {
            revocationInfo.getOcspResponseAttributes().put(RevocationInfo.KEY_OCSP_REQUEST, request);
        }
        if (response != null) {
            revocationInfo.getOcspResponseAttributes().put(RevocationInfo.KEY_OCSP_RESPONSE, response);
        }
        return revocationInfo;
    }

    private static CircuitBreakerConfig getCircuitBreakerConfig(CircuitBreakerConfig circuitBreakerConfig) {
        return CircuitBreakerConfig.from(circuitBreakerConfig)
            // Users must not be able to modify these three values.
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .ignoreExceptions(TaraUserCertificateRevokedException.class)
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .build();
    }

    private static RetryConfig getRetryConfigConfig(RetryConfig retryConfig) {
        return RetryConfig.from(retryConfig)
            // Users must not be able to modify this value.
            .ignoreExceptions(TaraUserCertificateRevokedException.class)
            .build();
    }
}
