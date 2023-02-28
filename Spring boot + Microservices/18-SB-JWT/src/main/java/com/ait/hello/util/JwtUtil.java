package com.ait.hello.util;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {

    private final String SECRET_KEY = "Q1!2JhkV7#2k";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
    	
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", userDetails.getUsername());
        claims.put("authorities", populateAuthorities(userDetails.getAuthorities()));
        return createToken(claims, userDetails.getUsername());
    }
    private String populateAuthorities(Collection<? extends GrantedAuthority> authorities) {
    	Set<String> hashSet = new HashSet<>();
    	for(GrantedAuthority c : authorities) {
    		hashSet.add(c.getAuthority());
    		
    	}
    	return hashSet.toString();
    }

    private String createToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
        		   .setClaims(claims)
        		   .setSubject(subject)
        		   .setIssuer("ashokit")
        		   .setIssuedAt(new Date(System.currentTimeMillis()))
        		   .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60))
        		   .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
        		   .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
