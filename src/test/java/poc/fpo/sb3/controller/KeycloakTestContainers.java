package poc.fpo.sb3.controller;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public abstract class KeycloakTestContainers {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTestContainers.class.getName());

    static final KeycloakContainer keycloak;

    static {
        keycloak = new KeycloakContainer().withRealmImportFile("keycloak/realm-test.json");
        keycloak.start();
    }

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri",
                () -> keycloak.getAuthServerUrl() + "realms/test");
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> keycloak.getAuthServerUrl() + "realms/test/protocol/openid-connect/certs");
    }

    protected String fetchAccessToken(String role) {

        String username = role.equals("ROLE_ADMIN") ? "darth" : "luke";

        try {
            URI authorizationURI =
                    new URIBuilder(keycloak.getAuthServerUrl() + "/realms/test/protocol/openid-connect/token").build();
            WebClient webclient = WebClient.builder().build();
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.put("scope", Collections.singletonList("openid"));
            formData.put("grant_type", Collections.singletonList("password"));
            formData.put("client_id", Collections.singletonList("test_client"));
            formData.put("client_secret", Collections.singletonList("**********"));
            formData.put("username", Collections.singletonList(username));
            formData.put("password", Collections.singletonList("password"));

            String result = webclient
                    .post()
                    .uri(authorizationURI)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            JacksonJsonParser jsonParser = new JacksonJsonParser();

            return "Bearer " + jsonParser.parseMap(result).get("access_token").toString();
        } catch (URISyntaxException e) {
            LOGGER.error("Can't obtain an access token from Keycloak!", e);
        }

        return null;
    }
}
