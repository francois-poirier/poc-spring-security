# Proof of concept Spring boot 3.1 / Spring Security 6 / keycloak

Here’s a list of the steps we will cover in this article:

Setting Up Our Keycloak Server:
Creating a Realm and Client
Creating a Client Role
Creating a User
Mapping the Client Role to our new User
Configuring our Spring Boot Project
Setting up our POM file
Setting up the Security Config
Setting the Application Properties
Setting Up Our Controller and Finishing Up
Controller set up
Testing It Out

## Setting Up Our Keycloak Server Env

Here is my script file: start-keycloak.sh
```script
#!/bin/bash
echo "* Starting Keycloak !"
docker compose up -d
sleep 90
echo "* Keycloak Started !"
echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * Luke user creation\n"
curl --location --request POST 'http://localhost:8080/admin/realms/test/users' -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '{ "createdTimestamp": 1588880747548, "username": "luke", "enabled": true, "totp": false, "emailVerified": false, "firstName": "Luke", "lastName": "Skywalker", "email": "luke.skywalker@jedi.com", "credentials":[{"type":"password","value":"password","temporary":false}], "disableableCredentialTypes": [], "requiredActions": [], "notBefore": 0, "access": { "manageGroupMembership": true, "view": true, "mapRoles": true, "impersonate": true, "manage": true }}'

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * Darth user creation\n"
curl --location --request POST 'http://localhost:8080/admin/realms/test/users' -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '{ "createdTimestamp": 1588880747548, "username": "darth", "enabled": true, "totp": false, "emailVerified": false, "firstName": "Darth", "lastName": "Wader", "email": "darth.wader@jedi.com", "credentials":[{"type":"password","value":"password","temporary":false}], "disableableCredentialTypes": [], "requiredActions": [], "notBefore": 0, "access": { "manageGroupMembership": true, "view": true, "mapRoles": true, "impersonate": true, "manage": true }}'
echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

ids=$(curl -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" "http://localhost:8080/admin/realms/test/users" | jq -r '.[].id')
echo "$ids"

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

id=($ids)
echo ${id[1]}

echo "\n"
echo " * map role app_user to luke user\n"
curl --location --request POST "http://localhost:8080/admin/realms/test/users/${id[1]}/role-mappings/realm" -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '[{ "id": "81c338bb-48db-42e4-a97e-d4bd5845859a", "name": "app_user"}]'

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * map role app_admin to darth user\n"
curl --location --request POST "http://localhost:8080/admin/realms/test/users/${id[0]}/role-mappings/realm" -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '[{ "id": "6e66c979-0820-463b-877d-6556521b02c9", "name": "app_admin"}]'

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * Get users \n"
curl http://localhost:8080/admin/realms/test/users -H "Authorization: bearer $TOKEN"

```
This script:
### Start the keycloak identity provider through a docker compose (The keycloak identity import realm define in a file realm-test.json already exists).  
### Wait 90 seconds for the server to be completely up
### Create 2 users and mapping the Client Role to our new users.

## How to run Application
Running application from command line using Maven, this is the cleanest way.

From the root directory you can run the following command:
mvn spring-boot:run
Application will be running on: http://localhost:8082

## Testing It Out
So let’s check this thing out! I’m using Postman as an API client, but you can use whatever you want. 
As we can see in our controller, our endpoint is just http://localhost:8082/users so I’ll send a GET request over to it previously generate a token JWT.

## Configuring our Spring Boot Project
### Setting up our POM
For our Spring Boot project, we need to add the spring-boot-starter-oauth2-resource-server dependency to our dependencies.
I will provide an example of our dependencies below. I am doing this in a maven project with a pom file.
```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

### Setting up the Security Config
With Spring Boot 3 and the deprecation of Keycloak’s libraries, we’ve lost easy access to a few things that we had previously. 
Most of them are outside of the scope of this article, but we do need to map the client roles from the Keycloak token to the SecurityContext in our application. Here is an example of the token we get from Keycloak:
```json
{
  "exp": 1688731025,
  "iat": 1688730725,
  "jti": "65c76edb-44b9-4fb7-82eb-b7b3ed0363d3",
  "iss": "http://localhost:32773/realms/test",
  "aud": "account",
  "sub": "2d282eca-4a3c-4683-a4e7-2974aaca18b9",
  "typ": "Bearer",
  "azp": "test_client",
  "session_state": "770c61bc-95d8-4305-a8ef-42f8ea9ef4ad",
  "acr": "1",
  "realm_access": {
    "roles": [
      "default-roles-test",
      "app_user",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "test_client": {
      "roles": [
        "VISITOR"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "sid": "770c61bc-95d8-4305-a8ef-42f8ea9ef4ad",
  "email_verified": false,
  "name": "Luke Skywalker",
  "preferred_username": "luke",
  "given_name": "Luke",
  "family_name": "Skywalker",
  "email": "luke.skywalker@jedi.com"
}
```

The values we want to grab is in the array of strings under resource_access > test_client (test_client represent the clientId). 
Luckily we can get that done pretty simply, right in our SecurityConfig class. So let’s do it:

```java
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .authorizeHttpRequests(registry -> registry
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2Configurer -> oauth2Configurer.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwt -> {

                    Map<String, Collection<String>> realmAccess = jwt.getClaim("resource_access");
                    Object client = realmAccess.get("test_client") ;
                    LinkedTreeMap<String, List<String>> clientRoleMap = (LinkedTreeMap<String, List<String>>) client;
                    List<String> clientRoles = new ArrayList<>(clientRoleMap.get("roles"));
                    var grantedAuthorities = clientRoles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toList());
                    return new JwtAuthenticationToken(jwt, grantedAuthorities);
                })))
        ;

        return httpSecurity.build();
    }
}
```

### Setting the Application Properties
Lastly we need to set up our app’s properties. I am using an application.yml file

```yaml
server:
  port: 8082

scheme: http
keycloak-port: 8080
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/test

spring:
  main:
    web-application-type: servlet
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${keycloak-issuer}
          jwk-set-uri: ${keycloak-issuer}/protocol/openid-connect/certs
```

And that’s it. Next up we will set up a controller and make sure our project works.

### Setting Up Our Controller and Finishing Up
#### Controller set up
Ok. We are in the final stretch. Let’s set up a super simple controller. We’re going to be adding in @PreAuthorize tag to our GET methods. 
This is what checks to make sure a user has the correct role to access the method. Here it is:
```java
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('ROLE_VISITOR')")
    public ResponseEntity user(Authentication authentication) {
        return ResponseEntity.ok(authentication.getName() + " access");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity admin(Authentication authentication) {
        return ResponseEntity.ok(authentication.getName() + " access");
    }
}
```
Inside our @PreAuthorize tag, we have another call to hasAuthority. 
This is where we give the role we want to check for. We can also use hasAnyAuthority if we want to check for any of a list of roles.

### Testing It Out with e2e test
So let’s check this thing out! I’m using testcontainers-keycloak library for implement the test.

This is my implementation.

```java
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
```

```java
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
public class UserControllerSecurityE2ETest extends KeycloakTestContainers {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Try to get user name access (request without Authorization header)")
    void shouldBeGetUnauthorized() throws Exception {

        mockMvc.perform(get("/users/user")).andDo(print()).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Try to get admin name access (request with Authorization header)")
    void shouldBeGetAdminNameAccess() throws Exception {

        String accessToken = fetchAccessToken("ROLE_ADMIN");

        mockMvc.perform(get("/users/admin").header("Authorization", accessToken))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Try to get admin name access having wrong role (request with Authorization header)")
    void shouldBeGetForbidden() throws Exception {

        String accessToken = fetchAccessToken("ROLE_VISITOR");

        mockMvc.perform(get("/users/admin").header("Authorization", accessToken))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Try to get user name access (request with Authorization header)")
    void shouldBeGetUserNameAccess() throws Exception {

        String accessToken = fetchAccessToken("ROLE_VISITOR");

        mockMvc.perform(get("/users/user").header("Authorization", accessToken))
                .andDo(print())
                .andExpect(status().isOk());
    }
}
```
