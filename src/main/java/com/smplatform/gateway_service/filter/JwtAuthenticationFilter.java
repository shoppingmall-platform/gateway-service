package com.smplatform.gateway_service.filter;

import com.smplatform.gateway_service.exception.TokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Setter
    public static class Config {
        private String secretKey;
    }

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        String secretKey = config.getSecretKey();

        return (exchange, chain) -> {
            try {
                List<String> auths = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
                if (auths == null) {
                    return redirectToLogin(exchange);
                }
                String jwt = auths.get(0);
                if (!jwt.startsWith("Bearer")) {
                    throw new TokenException("잘못된 토큰 형식입니다.");
                }

                Claims claims = getJwtClaim(secretKey, jwt.substring(7));
                ServerWebExchange modifiedExchange = exchange.mutate()
                        .request(r -> r.header("X-MEMBER-ID", claims.getSubject()).build())
                        .build();

                return chain.filter(modifiedExchange);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw new TokenException("key가 잘못되었습니다");
            }
        };
    }

    private Mono<Void> redirectToLogin(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.SEE_OTHER);
        exchange.getResponse().getHeaders().setLocation(URI.create("http://nginx/login"));
        return exchange.getResponse().setComplete();
    }

    private Claims getJwtClaim(String secretKey, String token) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey(secretKey);

        return Jwts.parser()
                .verifyWith(publicKey) // signature 검증
                .build()
                .parseSignedClaims(token) // 토큰 파싱 및 검증 (기한)
                .getPayload();
    }

    private PublicKey getPublicKey(String secretKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String s = secretKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(s);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // RSA 또는 EC
        return keyFactory.generatePublic(keySpec);
    }
}
