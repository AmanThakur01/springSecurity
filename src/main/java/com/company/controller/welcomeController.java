package com.company.controller;


import com.company.Jwt.JwtUtils;
import com.company.Jwt.LoginRequest;
import com.company.Jwt.LoginResponse;
import com.company.domain.*;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.naming.AuthenticationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class welcomeController {
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	AuthenticationManager authenticationManager;

	@GetMapping("/welcome")
	public String great() {
		return "Welcome Controller";
	}
	List<Student> list = new ArrayList<>(List.of(
			new Student("Aman", 9),
			new Student("Pratik", 10)));
	
	@PreAuthorize("hasRole('USER')")
	@GetMapping("/student")
	public List<Student> getStudent() {
		return list;
	}
	@GetMapping("/getCsrf")
	public CsrfToken getCsrfToken(HttpServletRequest req) {
		return (CsrfToken) req.getAttribute("_csrf");
	}
	
	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping("/student")
	public Student addStudent(@RequestBody Student student) {
		list.add(student);
		return student;
	}
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) throws AuthenticationException{
		Authentication authentication;
		authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(),
						loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
		System.out.println(jwtToken+"      -----token");
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item->item.getAuthority()).collect(Collectors.toList());
		LoginResponse response = new LoginResponse(jwtToken,userDetails.getUsername(),roles);
		return ResponseEntity.ok(response);
	}
	
	
}
