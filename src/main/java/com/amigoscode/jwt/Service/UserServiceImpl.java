package com.amigoscode.jwt.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.amigoscode.jwt.Model.AppUser;
import com.amigoscode.jwt.Model.Role;
import com.amigoscode.jwt.Repository.RoleRepository;
import com.amigoscode.jwt.Repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service @Transactional @RequiredArgsConstructor @Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

	private final UserRepository userRepo;
	private final RoleRepository roleRepo;
	private final PasswordEncoder passwordEncoder;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser user = userRepo.findByUsername(username);
		if (user == null) {
			log.error("User not found in the db: "+username);
			throw new UsernameNotFoundException("User not found in the db: "+username);
		}
		log.info("User found in the db: "+username);
		List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
		user.getRoles().stream().forEach(role->authorities.add(new SimpleGrantedAuthority(role.getName())));
		return new User(user.getUsername(), user.getPassword(), authorities);
	}
	
	@Override
	public AppUser saveUser(AppUser user) {
		log.info("Saving user "+user.getUsername());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving role "+role.getName());
		return roleRepo.save(role);
	}

	@Override
	public AppUser addRoleToUser(String username, String roleName) {
		log.info("Adding role "+roleName+" to user "+username);
		AppUser user = userRepo.findByUsername(username);
		Role role = roleRepo.findByName(roleName);
		user.getRoles().add(role);
		return user;

	}
	
	

	@Override
	public AppUser getUser(String username) {
		log.info("Fetching user by name "+username);
		return userRepo.findByUsername(username);
	}

	@Override
	public List<AppUser> getUsers() {
		log.info("Fetching all users");
		return userRepo.findAll();
	}

	@Override
	public void deleteUser(AppUser user) {
		userRepo.delete(user);
		
	}
	
	@Override
	public void deleteRole(Long roleId) {
		Role role = roleRepo.getById(roleId);
		
//		List<AppUser> affectedUsers = userRepo.findByRolesIn(Arrays.asList(role));
		userRepo.findAll().stream()
					 .forEach(user->user.getRoles().remove(role));
//		for(AppUser user:affectedUsers) {
//			user.getRoles().remove(role);
//		}
		roleRepo.delete(role);
					
	}

}
