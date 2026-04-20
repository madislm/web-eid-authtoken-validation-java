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

package eu.webeid.security.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.X509Certificate;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_RS256_AUTH_TOKEN;
import static org.assertj.core.api.Assertions.assertThatCode;

class AuthTokenSignatureValidatorTest {

    private static final ObjectReader OBJECT_READER = new ObjectMapper().readerFor(WebEidAuthToken.class);

    @Test
    void whenValidES384Signature_thenSucceeds() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_AUTH_TOKEN);
        final X509Certificate x509Certificate = CertificateLoader.decodeCertificateFromBase64(authToken.unverifiedCertificate());

        assertThatCode(() -> signatureValidator
            .validate("ES384", authToken.signature(), x509Certificate.getPublicKey(), VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenValidRS256Signature_thenSucceeds() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_RS256_AUTH_TOKEN);
        final X509Certificate x509Certificate = CertificateLoader.decodeCertificateFromBase64(authToken.unverifiedCertificate());

        assertThatCode(() -> signatureValidator
            .validate("RS256", authToken.signature(), x509Certificate.getPublicKey(), VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

}
