package poc.fpo.sb3.controller;

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