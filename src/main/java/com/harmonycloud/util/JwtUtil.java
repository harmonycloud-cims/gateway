package com.harmonycloud.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private RestTemplate template = new RestTemplate();

    private PublicKey publicKeyObject;

    @Value("${user-service.path.publicKey}")
    private String GET_PUBLIC_KEY_URL;

    @Value("${user-service.path.refreshToken}")
    private String REFRESH_TOKEN_URL;

    public String getPublicKey(){
        try {
            String key = template.getForObject(GET_PUBLIC_KEY_URL,String.class);
            return key;
        } catch (RestClientException e) {
            e.printStackTrace();
        }
        return null;
    }


    public String refreshToken(String oldToken){
        try {
            MultiValueMap<String, String> requestEntity = new LinkedMultiValueMap<String, String>();
            requestEntity.put("oldToken", Collections.singletonList(oldToken));
            Map<String,Object> result = template.postForObject(REFRESH_TOKEN_URL,requestEntity, Map.class);
            if((boolean)result.get("refresh")){
                String refreshToken = result.get("data").toString();
                return refreshToken;
            }
        } catch (RestClientException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Map<String,Object> validateToken(String authToken) {
        Map<String, Object> result = new HashMap<>();
        try {
            String publicKey = getPublicKey();
            if (!StringUtils.isEmpty(publicKey)) {
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
                KeyFactory x509KeyFactory = KeyFactory.getInstance("RSA");
                publicKeyObject = x509KeyFactory.generatePublic(x509KeySpec);
            }

            if (authToken != null) {
                try {
                    Claims claims = Jwts.parser().setSigningKey(publicKeyObject).parseClaimsJws(authToken).getBody();
                    result.put("access", true);
                    result.put("data", claims);
                    result.put("errorMsg", null);
                    return result;
                } catch (Exception e) {
                    result.put("access", false);
                    result.put("data", null);
                    result.put("errorMsg", e.getMessage());
                    return result;
                }
            } else {
                result.put("access", false);
                result.put("data", null);
                result.put("errorMsg", "token is null");
                return result;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return result;
    }
}
