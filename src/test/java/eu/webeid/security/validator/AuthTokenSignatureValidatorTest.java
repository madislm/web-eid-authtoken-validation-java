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
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenSignatureValidationException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_RS256_AUTH_TOKEN;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    @Test
    void whenRsaKeyIsTooShortForAlgorithm_thenThrowsAuthTokenSignatureValidationException() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final PublicKey weakPublicKey = keyPairGenerator.generateKeyPair().getPublic();

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_RS256_AUTH_TOKEN);

        // The public key comes from the unverified certificate of the token, so a key that JJWT refuses
        // to use must fail with a checked AuthTokenException, not with an unchecked JJWT exception.
        assertThatThrownBy(() -> signatureValidator
            .validate("RS256", authToken.signature(), weakPublicKey, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenSignatureValidationException.class);
    }

    @Test
    void whenEcKeyDoesNotMatchAlgorithm_thenThrowsAuthTokenSignatureValidationException() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        final PublicKey p256PublicKey = keyPairGenerator.generateKeyPair().getPublic();

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_AUTH_TOKEN);

        // ES512 requires a P-521 key, so JJWT rejects the P-256 key of the unverified certificate.
        assertThatThrownBy(() -> signatureValidator
            .validate("ES512", authToken.signature(), p256PublicKey, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenException.class);
    }

}
