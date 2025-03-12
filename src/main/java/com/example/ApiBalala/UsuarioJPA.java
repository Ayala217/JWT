package com.example.ApiBalala;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UsuarioJPA extends JpaRepository<UsuarioORM, Long> {
    Optional<UsuarioORM> findByUsername(String username);
}
