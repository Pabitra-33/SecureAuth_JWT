package security_for_login_registration.config;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

	private final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

	private final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

	// GENERATE TOKEN
	public String generateToken(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)).signWith(SECRET_KEY).compact();

	}

	// EXTRACT USERNAME
	public String extractUsername(String token) {
		return extractClaims(token).getSubject();
	}

	// validate token
	public boolean validateToken(String token, String username) {
		String extractedUser = extractUsername(token);
		return (username.equals(extractedUser) && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		return extractClaims(token).getExpiration().before(new Date());
	}

	private Claims extractClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody();

	}
}