package jwtsecurity.jwtsecuritylearn.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jwtsecurity.jwtsecuritylearn.model.AuthenticationResponse;
import jwtsecurity.jwtsecuritylearn.model.Token;
import jwtsecurity.jwtsecuritylearn.model.User;
import jwtsecurity.jwtsecuritylearn.repository.TokenRepository;
import jwtsecurity.jwtsecuritylearn.repository.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, TokenRepository tokenRepository) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.tokenRepository = tokenRepository;
    }

    public AuthenticationResponse register(User request) {
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername()); // Remove the unnecessary parentheses
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        user.setRole(request.getRole());
        user = repository.save(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        //save the generated jwt
        saveUserToken(accessToken, refreshToken, user);
        return new AuthenticationResponse(accessToken,refreshToken);
    }

    private void saveUserToken(String accessToken,String refreshToken,  User user) {
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticate(User request){
        authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                      request.getUsername(),
                      request.getPassword()
              )
        );
        User user = repository.findByUsername(request.getUsername()).orElseThrow();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        revokeAllTokenByUser(user);
        saveUserToken(accessToken, refreshToken, user);

        return new AuthenticationResponse(accessToken,refreshToken);

    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokenListByUser = tokenRepository.findAllAccessTokenByUser(user.getId());
        if(!validTokenListByUser.isEmpty()){
            validTokenListByUser.forEach(t->{
                t.setLoggedOut(true);
            });
        }
        tokenRepository.saveAll(validTokenListByUser);
    }

    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {

        //extract the token from authorization header
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader == null || !authHeader.startsWith("Bearer")){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

       String token =  authHeader.substring(7);
        //extract username from token

        String username = jwtService.extractUsername(token);

        //check if the user exist in the Database
        User user = repository.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("No user found"));

        //now check if refresh token is valid
        if(jwtService.isValidRefreshToken(token, user)){
            //generate access token
            String accessToken = jwtService.generateAccessToken(user);
           String refreshToken =  jwtService.generateRefreshToken(user);

           revokeAllTokenByUser(user);

           saveUserToken(accessToken,refreshToken,user);

           return new ResponseEntity(new AuthenticationResponse(accessToken,refreshToken), HttpStatus.OK);

        }


    return new ResponseEntity(HttpStatus.UNAUTHORIZED);

    }
}
