package security_for_login_registration.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import security_for_login_registration.service.CustomerService;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

	@Autowired
	private CustomerService customerService;

	@Autowired
	private JwtFilter jwtFilter;

	@Bean
	DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authprovider = new DaoAuthenticationProvider();
		authprovider.setPasswordEncoder(passwordEncoder());
		authprovider.setUserDetailsService(customerService);
		return authprovider;
	}

	@Bean
	AuthenticationManager authManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	// THIS ONE IS FOR GIVING A PARTICULAR APIS NO SECURITYB LIKE HOME AND HELP PAGE
	// CAN ACCESS BY ALL
	@Bean
	SecurityFilterChain security(HttpSecurity http, JwtFilter jwtfilter) throws Exception {

		http.authorizeHttpRequests(
				req -> req.requestMatchers("/register", "/login").permitAll().anyRequest().authenticated());
		http.addFilterBefore(jwtfilter, UsernamePasswordAuthenticationFilter.class);
		return http.csrf().disable().build();

	}

	@Bean
	PasswordEncoder passwordEncoder() // USED FOR ENCRYPTING THE PASSWORD OF USER
	{
		return new BCryptPasswordEncoder();
	}
}