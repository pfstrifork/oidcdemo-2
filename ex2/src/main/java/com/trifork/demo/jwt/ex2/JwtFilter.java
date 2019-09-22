package com.trifork.demo.jwt.ex2;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class JwtFilter extends GenericFilterBean {
    private static final Logger logger = LoggerFactory.getLogger(DemoApplication.class);

    private static final String requiredScope = "serviceklient";

    private VerificationKeyResolver keyresolver;

    public JwtFilter() {
        try {
            HttpsJwks httpsJkws = new HttpsJwks("https://topdanmark.id42.dk/auth/realms/demo/protocol/openid-connect/certs");
            keyresolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
        } catch (Exception e) {
            logger.error("Failed to create keyresolver:", e);
            throw new RuntimeException("Could not initialise JwtFilter");
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        logger.info("Method " + request.getMethod());

        if (isAuthorized(request)) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            response.setStatus(401);
            response.getOutputStream().write("Go away".getBytes());
            return;
        }
    }

    private boolean isAuthorized(HttpServletRequest request) {
        try {
            String jwt = getJwtToken(request);
            if (jwt != null) {
                JwtClaims jwtClaims = validateJwt(jwt);
                if (verifyScope(jwtClaims, requiredScope)) {
                    return true;
                } else {
                    logger.error("Required scope not present");
                }
            } else {
                logger.error("No JWT present");
            }
        } catch (InvalidJwtException e) {
            logger.error("Invalid JWT", e);
        }
        return false;
    }

    private boolean verifyScope(JwtClaims jwtClaims, String requiredScope)  {
        try {
            String claimedScopes = jwtClaims.getStringClaimValue("scope");
            if (claimedScopes == null) {
                return false;
            }
            for (String claimedScope : claimedScopes.split("\\s+")) {
                if (requiredScope.equals(claimedScope)) {
                    return true;
                }
            }
        } catch (MalformedClaimException e) {
            logger.error("Malformed scope claim", e);
        }
        return false;
    }

    private String getJwtToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            String jwtPrefix = "Bearer ";
            if (authorizationHeader.startsWith(jwtPrefix)) {
                return authorizationHeader.substring(jwtPrefix.length());
            }
        }
        return authorizationHeader;
    }

    private JwtClaims validateJwt(String jwt) throws InvalidJwtException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setVerificationKeyResolver(keyresolver)
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256))
                .setMaxFutureValidityInMinutes(1)
                .setExpectedAudience(true, "api1")
                .setExpectedIssuer(true, "https://topdanmark.id42.dk/auth/realms/demo")
                .setRequireSubject()
                .setAllowedClockSkewInSeconds(10000000)
                .build();

        return jwtConsumer.processToClaims(jwt);
    }

    @Override
    public void destroy() {
    }
}
