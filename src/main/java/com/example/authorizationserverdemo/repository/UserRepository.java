package com.example.authorizationserverdemo.repository;

import com.example.authorizationserverdemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username);
}
