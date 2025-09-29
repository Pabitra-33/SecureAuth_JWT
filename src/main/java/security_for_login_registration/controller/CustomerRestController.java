package security_for_login_registration.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import security_for_login_registration.config.JwtUtil;
import security_for_login_registration.entity.Customer;
import security_for_login_registration.service.CustomerService;

@RestController
public class CustomerRestController {

	@Autowired
	private CustomerService customerService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtUtil jwtUtil;

	@PostMapping("/register")
	public ResponseEntity<String> register(@RequestBody Customer customer) {
		boolean status = customerService.saveCustomer(customer);

		if (status) {
			return new ResponseEntity<String>("SUCCESS", HttpStatus.CREATED);
		} else {
			return new ResponseEntity<String>("FAILED", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@PostMapping("/login") // Request body is for JSON to java object
	public ResponseEntity<String> login(@RequestBody Customer customer) {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(customer.getEmail(),
				customer.getPswd());
		Authentication authenticate = authenticationManager.authenticate(token);

		if (authenticate.isAuthenticated()) {
			String jwt = jwtUtil.generateToken(customer.getEmail());
			return new ResponseEntity<>(jwt, HttpStatus.OK);
		} else {
			return new ResponseEntity<>("Failed", HttpStatus.BAD_REQUEST);
		}

	}

	// SECURED API/End-point we can't access this
	@GetMapping("/hello")
	public String hello() {
		return "HELLO, WELCOME TO Secured Api hello";
	}
}