package com.amigoscode.jwt.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.amigoscode.jwt.Model.AppUser;

public interface UserRepository extends JpaRepository<AppUser, Long> {
	AppUser findByUsername(String username);
}
