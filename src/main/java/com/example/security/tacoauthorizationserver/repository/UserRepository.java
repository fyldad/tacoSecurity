package com.example.security.tacoauthorizationserver.repository;

import com.example.security.tacoauthorizationserver.model.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User, String> {
    Optional<User> findUserByUsername(String username);
}
