
package com.adriandlph.encryption.jwt;

import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import java.util.Calendar;
import java.util.Map;

/**
 *
 * @author adriandlph
 *
 */
public class JWT {

	/**
	 * 
	 * Generate a JSON Web Token.
	 * 
	 * @param algorithm Algorithm used to generate JWT token
	 * @param subject Token subject
	 * @param issuer issuer 
	 * @param issuedAt issuer 
	 * @param expires Time until token is valid
	 * @param claims Claims
	 * 
	 * @return Token in string format.
	 * 
	 */
	public static String generateToken(Algorithm algorithm, String subject, String issuer, Calendar issuedAt, Calendar expires, Map<String,Object> claims) throws IllegalArgumentException, JWTCreationException {
		JWTCreator.Builder tokenBuilder;
		
		if (algorithm == null) return null;
		
		// Add data of the token
		tokenBuilder = com.auth0.jwt.JWT.create();
		if (subject != null) tokenBuilder = tokenBuilder.withSubject(subject);
		if (issuer != null) tokenBuilder = tokenBuilder.withIssuer(issuer);
		if (issuedAt != null) tokenBuilder = tokenBuilder.withIssuedAt(issuedAt.toInstant());
		if (expires != null) tokenBuilder = tokenBuilder.withExpiresAt(expires.toInstant());
		if (claims != null) tokenBuilder = tokenBuilder.withHeader(claims);
		
		// Generate and sign token
		return tokenBuilder.sign(algorithm);
	}
	
	public static DecodedJWT decodeToken(Algorithm algorithm, String token, String subject, String issuer) throws TokenExpiredException, JWTVerificationException {
		DecodedJWT decodedJWT;
		Verification verification;
		
		if (token == null) return null;
        
		// Create verificator
		verification = com.auth0.jwt.JWT.require(algorithm);
		if (subject != null) verification = verification.withSubject(subject);
		if (issuer != null) verification = verification.withIssuer(issuer);
		
		// Verify and decode JWT
		decodedJWT = verification.build().verify(token);
		
        return decodedJWT;

		
	}
	
}
