package com.example.jwt.repo;

import com.example.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

//    Optional<User> findByEmail(String email);

    Optional<User> findByUserNameOrUserEmail(String username, String email);

//    List<User> findByIdIn(List<Long> userIds);
//
//    Optional<User> findByUsername(String username);
//
    Boolean existsByUserName(String username);

    Boolean existsByUserEmail(String email);
}
