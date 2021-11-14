package com.amigoscode.jwt.Model;

import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity @Data @AllArgsConstructor @NoArgsConstructor
public class Role {
	@Id @GeneratedValue(strategy = GenerationType.AUTO)
	private Long Id;
	private String name;
}
