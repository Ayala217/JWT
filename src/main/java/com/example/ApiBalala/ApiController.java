package com.example.ApiBalala;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ApiController {
    @GetMapping("/admin/data")
    public String adminEndpoint() {
        return "Datos exclusivos para admin";
    }

    @GetMapping("/user/data")
    public String userEndpoint() {
        return "Datos exclusivos para usuario";
    }

    @GetMapping("/shared/data")
    public String sharedEndpoint() {
        return "Datos compartidos";
    }
}
