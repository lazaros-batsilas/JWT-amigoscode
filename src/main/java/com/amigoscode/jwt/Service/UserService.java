package com.amigoscode.jwt.Service;

import java.util.List;

import com.amigoscode.jwt.Model.AppUser;
import com.amigoscode.jwt.Model.Role;

public interface UserService {
	
	AppUser saveUser(AppUser user);
	Role saveRole(Role role);
	AppUser addRoleToUser(String username, String role);
	AppUser getUser(String username);
	List<AppUser> getUsers();
	void deleteUser(AppUser user);
	void deleteRole(Long roleId);
	void deleteRoleFromUser(String username, Long roleId);
	
}
