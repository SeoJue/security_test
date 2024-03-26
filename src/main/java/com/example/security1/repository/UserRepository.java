package com.example.security1.repository;

import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

//SpringDataJpa
public interface UserRepository extends JpaRepository<User, Long> {
    //findBy 규칙 -> findBy + parameter   (Data Jpa query method)
    public User findByUsername(String username);

}
