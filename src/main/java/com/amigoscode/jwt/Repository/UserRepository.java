package com.amigoscode.jwt.Repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.amigoscode.jwt.Model.AppUser;
import com.amigoscode.jwt.Model.Role;

public interface UserRepository extends JpaRepository<AppUser, Long> {
	AppUser findByUsername(String username);
	List<AppUser> findByRolesIn(List<Role> roles);
}
