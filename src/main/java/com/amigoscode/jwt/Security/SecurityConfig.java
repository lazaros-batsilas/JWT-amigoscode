package com.amigoscode.jwt.Security;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.http.HttpMethod.DELETE;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.amigoscode.jwt.Filter.CustomAuthenticationFilter;
import com.amigoscode.jwt.Filter.CustomAuthorizationFilter;
import com.amigoscode.jwt.Utils.ErrorUtils;
import com.amigoscode.jwt.Utils.JWTUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration @EnableWebMvc @RequiredArgsConstructor @Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final UserDetailsService userDetailsService;
	private final BCryptPasswordEncoder bcryptPasswordEncoder;
	private final JWTUtils jwtUtils;
	private final ErrorUtils errorUtils;


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService)
			.passwordEncoder(bcryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean(), jwtUtils);
		customAuthenticationFilter.setFilterProcessesUrl("/api/login");
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();
		http.authorizeRequests().antMatchers(GET, "/api/users/**").hasAnyAuthority("ROLE_USER", "ROLE_MANAGER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN");
		http.authorizeRequests().antMatchers(POST, "/api/**").hasAnyAuthority("ROLE_MANAGER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN");
		http.authorizeRequests().antMatchers(PUT, "/api/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPER_ADMIN");
		http.authorizeRequests().antMatchers(DELETE, "/api/**").hasAnyAuthority("ROLE_SUPER_ADMIN");
		http.authorizeRequests().anyRequest().authenticated();
		http.addFilter(customAuthenticationFilter);
		http.addFilterBefore(new CustomAuthorizationFilter(jwtUtils, errorUtils, userDetailsService), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
