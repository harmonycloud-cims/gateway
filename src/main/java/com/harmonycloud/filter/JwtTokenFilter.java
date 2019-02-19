package com.harmonycloud.filter;

import com.harmonycloud.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenFilter implements GlobalFilter, Ordered{

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        logger.info("I am In:{}",request.getURI());
        logger.info(request.getMethod().toString());
        try {
            HttpHeaders headers = request.getHeaders();
            String token = getToken(headers);

            ServerHttpResponse response = exchange.getResponse();
            if (!StringUtils.isEmpty(token)) {
                Map<String, Object> result = jwtUtil.validateToken(token);
                if ((boolean) result.get("access")) {
                    Claims claims = (Claims) result.get("data");
                    long expireTime = claims.getExpiration().getTime();
                    String userId = claims.get("userId").toString();
                    // IstIo 使用，需要在header中明文传输一个userId
                    exchange.mutate().request(request.mutate().header("userId",userId).build()).build();

                    if (expireTime - new Date().getTime() > 5 * 60 * 1000) {
                        //token快要过期，（刷新token）重新生成一个新的token
                        String newToken  = jwtUtil.refreshToken(token);
                        if(!StringUtils.isEmpty(newToken)){
                            ServerWebExchange build = exchange.mutate().request(request.mutate()
                                    .headers(httpHeaders -> httpHeaders.set("Authorization", "Bearer "+newToken)).build()).build();
                            return chain.filter(build);
                        }
                    }
                    return chain.filter(exchange);
                } else {
                    logger.info("token is Invalid");
                    //token 是无效的
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    String msg = (String)result.get("errorMsg");
                    byte[] bytes = ("{\"msg\":"+msg+"}").getBytes(StandardCharsets.UTF_8);
                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                    return response.writeWith(Flux.just(buffer));
                }
            }

        } catch (Exception e) {
            logger.info("error happened {}:",e);
            e.printStackTrace();

        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }


    private String getToken(HttpHeaders headers) {
        String bearerToken = headers.getFirst("Authorization");
        System.out.println("token:");
        System.out.println(bearerToken+"\n");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
