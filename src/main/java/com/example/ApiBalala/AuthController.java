package com.example.ApiBalala;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UsuarioJPA usuarioJPA;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController ( UsuarioJPA usuarioJPA , AuthenticationManager authenticationManager , PasswordEncoder passwordEncoder , JwtUtil jwtUtil ) {
        this.usuarioJPA = usuarioJPA;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public String register ( @RequestBody UsuarioORM user ) {
        if (user.getRole () == null || user.getRole ().isEmpty ()) {
            user.setRole ( "ROLE_USER" ); // Rol por defecto
        }
        user.setPassword ( passwordEncoder.encode ( user.getPassword () ) );
        usuarioJPA.save ( user );
        return "Usuario registrado con éxito";
    }

    @PostMapping("/login")
    public String login ( @RequestBody LoginRequest request ) {
        try {
            authenticationManager.authenticate ( new UsernamePasswordAuthenticationToken ( request.username () , request.password () ) );

            // Buscar usuario en la base de datos
            UsuarioORM usuario = usuarioJPA.findByUsername ( request.username () )
                    .orElseThrow ( () -> new RuntimeException ( "Usuario no encontrado" ) );

            // Generar el token con el rol del usuario
            return jwtUtil.generateToken ( usuario.getUsername () , usuario.getRole () );
        } catch (Exception e) {
            return "Error: Credenciales incorrectas";
        }
    }


    record LoginRequest(String username , String password) {
    }

}
