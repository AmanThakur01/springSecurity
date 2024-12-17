package com.company.conf;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.company.Jwt.AuthEntryPointJwt;
import com.company.Jwt.AuthTokenFilter;



@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	DataSource dataSource;
	
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;
	
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}
	@Bean
	 SecurityFilterChain getSecurityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(authorizeRequest->authorizeRequest
				.requestMatchers("/h2-console/**").permitAll().
				requestMatchers("/signin").permitAll().
				anyRequest().authenticated());
		
		http.sessionManagement(Session -> Session.
				sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		http.exceptionHandling(exception -> exception.
				authenticationEntryPoint(unauthorizedHandler));
		
		http.headers(headers->headers.
				frameOptions(frameOptions ->frameOptions.
						sameOrigin()));
		
		http.csrf(csrf-> csrf.disable());
		
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
//		http.csrf(Customizer -> Customizer.disable());
		
		
//		http.formLogin(Customizer.withDefaults());
//		http.httpBasic(Customizer.withDefaults());
//		
		return http.build();
		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
//	@Bean 
//	public UserDetailsService userDetailService() {
//		UserDetails user1 = User.withUsername("user1")
//				.password(passwordEncoder().encode("pwd1"))
//				.roles("USER")
//				.build();
//		UserDetails admin1 = User.withUsername("admin1")
//				.password(passwordEncoder().encode("pwd2"))
//				.roles("ADMIN")
//				.build();
//		
//		JdbcUserDetailsManager userDetailManager = new JdbcUserDetailsManager(dataSource);
//		
//		userDetailManager.createUser(user1);
//		userDetailManager.createUser(admin1);
//		return userDetailManager;
////		return new InMemoryUserDetailsManager(user1,admin1);
//	}
	
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}
	
	@Bean
	public CommandLineRunner initDaata(UserDetailsService userDetailsService) {
		return args ->{
//			JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
			UserDetails user1 = User.withUsername("user1")
					.password(passwordEncoder().encode("pwd1"))
					.roles("USER")
					.build();
			UserDetails admin1 = User.withUsername("admin1")
					.password(passwordEncoder().encode("pwd2"))
					.roles("ADMIN")
					.build();
			JdbcUserDetailsManager userDetailManager = new JdbcUserDetailsManager(dataSource);
			
			userDetailManager.createUser(user1);
			userDetailManager.createUser(admin1);
//			return userDetailManager;
		};
	}
	@Bean 
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}
}
