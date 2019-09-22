package com.trifork.demo.jwt.ex1;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@SpringBootApplication
public class DemoApplication implements CommandLineRunner {
	private static final Logger logger = LoggerFactory.getLogger(DemoApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Override
	public void run(String... args) throws FileNotFoundException, CertificateException {
		logger.info("Hello world!");

		String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJRLUxwZ0VjN1BPa1FzT19SMFlkTllrN3RSUGh2ZFM5bkJwTUNIMk1kWkNFIn0.eyJqdGkiOiI2YzhjNzUxNS1mMjIwLTRhNzItYmE3Yy1jZjVhMTM1OTcwNGYiLCJleHAiOjE1NjkxNTEwOTQsIm5iZiI6MCwiaWF0IjoxNTY5MTUwNzk0LCJpc3MiOiJodHRwczovL3RvcGRhbm1hcmsuaWQ0Mi5kay9hdXRoL3JlYWxtcy9kZW1vIiwiYXVkIjoiYXBpMSIsInN1YiI6IjIwNTA2NTQ3LTU2MDUtNGEwMy1hZmFmLWYyOGYxMDA0MDdkZiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlbW9rbGllbnQxIiwibm9uY2UiOiJ5YXA1N0lRYUZ5bFAweWhkNDMwTWh4UWtCLXFOVjh4eC1QM0YzZGw5VU5nIiwiYXV0aF90aW1lIjoxNTY5MTUwMTgwLCJzZXNzaW9uX3N0YXRlIjoiZDUwNDdlYWUtZmZjNS00MzNhLWExMmQtMjI4NjI4YjA2ZjRmIiwiYWNyIjoiMCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZGVtb2tsaWVudDEgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlBldGVyIEZsaW50aG9sbSIsInByZWZlcnJlZF91c2VybmFtZSI6InBldGVyIiwiZ2l2ZW5fbmFtZSI6IlBldGVyIiwiZmFtaWx5X25hbWUiOiJGbGludGhvbG0iLCJlbWFpbCI6InBmc0B0cmlmb3JrLmNvbSJ9.Zv-940vShunrAcAi5aaHUezPZh9WnzNf7Og4muAZg39rdyp6Cqx1OOFzKGi3hnyE-3PfpcDrXtXwq2nqrNcXuEMLWXN04LGOwmPN0EAy3BMKLkivT98Ht_3DtuV8MrkwDge7pbzjUDzRXXbqWozmwRVNaa15t0Q8kM-w_KpnKYok7az3dIC6YRyaIrJO68T1Y8ZOFIpNJ-AD4BGW7B10_tVrmnhcIRcp5owXZXSqWaQNe0A0YhdFTjq7qlk1D71m2scYtMoIVLEzj72aepA8eFiRDPCVOVqDKhup8wDPIm9JCnrz31dowyKCkks0qyvcb9t55IWBQmth1ZOIgXq0-w";
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate)cf.generateCertificate(new FileInputStream("oidc_public.pem"));

			X509VerificationKeyResolver keyresolver = new X509VerificationKeyResolver(cert);
			keyresolver.setTryAllOnNoThumbHeader(true);

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

			JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
			logger.info("JWT token is valid : " + jwtClaims);

			String scopes = (String)jwtClaims.getClaimValue("scope");
			String[] scopeList = scopes.split("\\s+");

			logger.info("Scopes {}", scopes);

			// Authorize based on scopes and other claims for identity
		} catch (InvalidJwtException e) {
			logger.info(e.getMessage());
			logger.info("JWT token is INVALID.");
		}
	}
}
