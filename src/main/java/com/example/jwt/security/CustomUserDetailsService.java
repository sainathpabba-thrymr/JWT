package com.example.jwt.security;

import com.example.jwt.model.User;
import com.example.jwt.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
// Let people login with either username or email
        User user = userRepository.findByUserNameOrUserEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with username or email : " + usernameOrEmail)
                );
        return UserPrincipal.create(user);
    }

    @Transactional
    public UserDetails loadUserById(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new UsernameNotFoundException("User not found with id : " + userId)
        );
        return UserPrincipal.create(user);
    }
}
