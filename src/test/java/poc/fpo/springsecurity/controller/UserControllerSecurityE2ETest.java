package poc.fpo.springsecurity.controller;

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
