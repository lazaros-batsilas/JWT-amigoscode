package com.amigoscode.jwt;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.amigoscode.jwt.Model.AppUser;
import com.amigoscode.jwt.Model.Role;
import com.amigoscode.jwt.Service.UserService;

@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}
	
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(10);
	}
	
//	@Bean
//	CommandLineRunner run(UserService userService) {
//		return args->{
//			userService.saveRole(new Role(null, "ROLE_USER"));
//			userService.saveRole(new Role(null, "ROLE_MANAGER"));
//			userService.saveRole(new Role(null, "ROLE_ADMIN"));
//			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//			
//			userService.saveUser(new AppUser(null, "John Travolta", "john", "pass", new ArrayList<Role>()));
//			userService.saveUser(new AppUser(null, "Will Smith", "will", "pass", new ArrayList<Role>()));
//			userService.saveUser(new AppUser(null, "Jim Carey", "jim", "pass", new ArrayList<Role>()));
//			userService.saveUser(new AppUser(null, "Arnold Schwarzenegger", "arnold", "pass", new ArrayList<Role>()));
//
//			userService.addRoleToUser("john", "ROLE_USER");
//			userService.addRoleToUser("john", "ROLE_MANAGER");
//			userService.addRoleToUser("will", "ROLE_MANAGER");
//			userService.addRoleToUser("jim", "ROLE_ADMIN");
//			userService.addRoleToUser("arnold", "ROLE_SUPER_ADMIN");
//			userService.addRoleToUser("arnold", "ROLE_ADMIN");
//			userService.addRoleToUser("arnold", "ROLE_USER");
//
//		};
//	}

}
