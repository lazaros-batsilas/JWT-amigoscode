package com.amigoscode.jwt.Utils;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ErrorUtils {
	public void writeErrorToBody(Exception exception, HttpServletResponse response) {
		log.error(exception.getStackTrace().toString());
		
		try {		
			response.addHeader("error", "Error authorizing user "+exception.getMessage());
			response.setStatus(FORBIDDEN.value());
			//response.sendError(FORBIDDEN.value());
			Map<String, String> error = new HashMap<String, String>();
			error.put("error_message", exception.getMessage());
			response.setContentType(APPLICATION_JSON_VALUE);
			new ObjectMapper().writeValue(response.getOutputStream(), error);
		}catch (Exception e){
			
			throw new IllegalStateException("Could not write error to response body");
			
		}
	}
	
}
