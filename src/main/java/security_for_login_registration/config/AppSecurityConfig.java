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
import org.springframework.security.web.SecurityFilterChain;

import security_for_login_registration.service.CustomerService;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

	@Autowired
	private CustomerService customerService;

	@Autowired
	private JwtFilter jwtFilter;

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authprovider = new DaoAuthenticationProvider();

		authprovider.setPasswordEncoder(pwdEncoder());
		authprovider.setUserDetailsService(customerService);
		return authprovider;
	}

	@Bean
	public AuthenticationManager authManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

//	@Bean
//	public SecurityFilterChain security(HttpSecurity http) throws Exception
//	{
//		http.authorizeRequests((req)->req.requestMatchers("/register","/login").permitAll().anyRequest().authenticated());
//	return http.csrf().disable().build();

	// jwt.............
	@Bean
	public SecurityFilterChain security(HttpSecurity http) throws Exception {

		http.authorizeRequests(
				(req) -> req.requestMatchers("/register", "/login").permitAll().anyRequest().authenticated());
		http.addFilterBefore(jwtFilter,
				org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
		return http.csrf().disable().build();

	}

	@Bean
	public BCryptPasswordEncoder pwdEncoder() // this is used to encrypt password given by user
	{
		return new BCryptPasswordEncoder();
	}

}