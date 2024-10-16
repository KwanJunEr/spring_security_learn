package jwtsecurity.jwtsecuritylearn.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jwtsecurity.jwtsecuritylearn.model.User;
import jwtsecurity.jwtsecuritylearn.repository.TokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    private TokenRepository tokenRepository;
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isValid(String token, UserDetails user){
        String username = extractUsername(token);
        boolean isValidToken = tokenRepository.findByAccessToken(token)
                .map(t->!t.isLoggedOut()).orElse(false);
        return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    public <T> T extractClaim(String token, Function<Claims, T> resolver){
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    public String generateAccessToken(User user) {
        return generateToken(user, accessTokenExpire); //86400000

    }




    public String generateRefreshToken(User user) {

       return generateToken(user, refreshTokenExpire);  //604800000
    }

    private String generateToken(User user, long expireTime){
        String token = Jwts
                .builder()
                .setSubject(user.getUsername()) // Use setSubject() instead of .subject() for correctness
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTime)) // 24 hours expiration
                .signWith(getSignInKey()) // Sign with your signing key
                .compact();

        return token;
    }

    private SecretKey getSignInKey(){
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isValidRefreshToken(String token, User user) {
        String username = extractUsername(token);

        boolean isValidRefreshToken = tokenRepository.findByRefreshToken(token)
                .map(t->!t.isLoggedOut()).orElse(false);

        return (username.equals(user.getUsername())) && !isTokenExpired(token) && isValidRefreshToken;
    }
}
