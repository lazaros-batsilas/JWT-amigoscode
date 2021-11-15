package com.amigoscode.jwt.Filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import com.amigoscode.jwt.Utils.ErrorUtils;
import com.amigoscode.jwt.Utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter{
	private final JWTUtils jwtUtils;
	private final ErrorUtils errorUtils;
	private final UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		if (request.getServletPath().equals("/api/login") ||
			request.getServletPath().equals("/api/token/refresh")){
			filterChain.doFilter(request, response);
		} else {
			String authorizationHeader = request.getHeader("Authorization");
			log.info("Authorization header: "+authorizationHeader);
			if((authorizationHeader!=null)&&(authorizationHeader.startsWith("Bearer ")))
			{
				
				try{				
					
					String token = authorizationHeader.substring("Bearer ".length());
					String username = jwtUtils.extractUsername(token);
					
					UserDetails userDetails = userDetailsService.loadUserByUsername(username);
					if(jwtUtils.validateToken(token, userDetails)){
						Claims claims = jwtUtils.extractAllClaims(token);
						ArrayList<String> roles = (ArrayList<String>) claims.get("roles");
						Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
						roles.stream().forEach(role->authorities.add(new SimpleGrantedAuthority(role)));
						UsernamePasswordAuthenticationToken authenticationToken
							= new UsernamePasswordAuthenticationToken(username, null, authorities);
						SecurityContextHolder.getContext().setAuthentication(authenticationToken);
						filterChain.doFilter(request, response);
						
					}
					

					
				} catch (Exception exception){
					errorUtils.writeErrorToBody(exception, response);
				}

			} else {
				filterChain.doFilter(request, response);
			}
		}

	}
}
