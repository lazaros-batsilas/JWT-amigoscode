package com.amigoscode.jwt.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.amigoscode.jwt.Model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
	Role findByName(String name);
}
