package com.amigoscode.jwt.Controller;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.amigoscode.jwt.Model.AppUser;
import com.amigoscode.jwt.Model.Role;
import com.amigoscode.jwt.Service.UserService;
import com.amigoscode.jwt.Utils.ErrorUtils;
import com.amigoscode.jwt.Utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserController {
	
	private final UserService userService;
	private final UserDetailsService userDetailsService;
	private final JWTUtils jwtUtils;
	private final ErrorUtils errorUtils;
	
	@GetMapping("/users")
	ResponseEntity<List<AppUser>> getUsers(){
		return ResponseEntity.ok().body(userService.getUsers());
	}
	
	
	@PostMapping("/user/save")
	ResponseEntity<AppUser> saveUser(@RequestBody AppUser user){
		URI uri = URI.create(ServletUriComponentsBuilder
				.fromCurrentContextPath()
				.path("api/user/save").toUriString());
		return ResponseEntity.created(uri).body(user);
	}
	
	
	@PostMapping("/role/save")
	ResponseEntity<Role> saveRole(@RequestBody Role role){
		URI uri = URI.create(ServletUriComponentsBuilder
				.fromCurrentContextPath()
				.path("/api/role/save").toUriString());
		return ResponseEntity.created(uri).body(role);
	}
	
	@PostMapping("/role/addToUser")
	ResponseEntity<AppUser> addRoleToUser(@RequestBody RoleUserForm form){
		return ResponseEntity.ok().body(userService.addRoleToUser(form.getName(),form.getRole()));
	}
	
	@GetMapping("/token/refresh")
	void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException{
		String authorizationHeader = request.getHeader("Authorization");
		if((authorizationHeader!=null)&&(authorizationHeader.startsWith("Bearer ")))
		{
			
			try{
				
				String refresh_token = authorizationHeader.substring("Bearer ".length());
				String username = jwtUtils.extractUsername(refresh_token);
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);											
				if(jwtUtils.validateToken(refresh_token, userDetails)) {
					
					String access_token = jwtUtils.generateToken(userDetails);
					Map<String, String> tokens = new HashMap<String, String>();
					tokens.put("access_token", access_token);
					tokens.put("refresh_token", refresh_token);
					response.setContentType(APPLICATION_JSON_VALUE);
					new ObjectMapper().writeValue(response.getOutputStream(), tokens);
					
					
				} else {
					
					throw new IllegalStateException("Invalid refresh token");
				}
								
			} catch (Exception exception){
				
				errorUtils.writeErrorToBody(exception, response);
			}

		} else {
			throw new RuntimeException("refresh token is missing");
		}
	}
	
}

@Data
class RoleUserForm{
	private String name;
	private String role;
}
